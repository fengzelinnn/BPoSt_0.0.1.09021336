use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::P2PSimConfig;
use crate::crypto::{folding::NovaFoldingCycle, serialize_g2};
use crate::roles::file_owner::FileOwner;
use crate::utils::{log_msg, with_cpu_heavy_limit};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommandRequest {
    cmd: String,
    #[serde(default)]
    data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommandResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Clone)]
struct StoredFileRecord {
    _nodes: Vec<SocketAddr>,
    _num_chunks: usize,
    required_rounds: usize,
    final_verified: bool,
}

pub struct UserNode {
    owner: FileOwner,
    host: String,
    port: u16,
    bootstrap_addr: SocketAddr,
    config: P2PSimConfig,
    stop_flag: Arc<AtomicBool>,
    bids: Arc<Mutex<HashMap<String, Vec<Value>>>>,
    active_requests: Arc<Mutex<HashSet<String>>>,
    stored_files: Arc<Mutex<HashMap<String, StoredFileRecord>>>,
    broadcast_buffer: Arc<Mutex<VecDeque<CommandRequest>>>,
}

impl UserNode {
    pub fn new(
        owner: FileOwner,
        host: String,
        port: u16,
        bootstrap_addr: SocketAddr,
        config: P2PSimConfig,
    ) -> Self {
        Self {
            owner,
            host,
            port,
            bootstrap_addr,
            config,
            stop_flag: Arc::new(AtomicBool::new(false)),
            bids: Arc::new(Mutex::new(HashMap::new())),
            active_requests: Arc::new(Mutex::new(HashSet::new())),
            stored_files: Arc::new(Mutex::new(HashMap::new())),
            broadcast_buffer: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    pub fn run(mut self) {
        let addr = SocketAddr::new(self.host.parse().unwrap(), self.port);
        let listener = match TcpListener::bind(addr) {
            Ok(l) => l,
            Err(e) => {
                log_msg(
                    "CRITICAL",
                    "USER_NODE",
                    Some(self.owner.owner_id.clone()),
                    &format!("启动服务器失败: {}", e),
                );
                return;
            }
        };
        log_msg(
            "INFO",
            "USER_NODE",
            Some(self.owner.owner_id.clone()),
            &format!("用户节点已在 {}:{} 启动", self.host, self.port),
        );

        // 克隆共享状态，用于监听线程
        let stop_flag = Arc::clone(&self.stop_flag);
        let broadcast_buffer = Arc::clone(&self.broadcast_buffer);
        let owner_id = self.owner.owner_id.clone();

        // 启动监听线程，处理 accept 循环与连接
        thread::spawn(move || {
            // 将监听器移入线程，并采用非阻塞以便响应停止信号
            if let Err(e) = listener.set_nonblocking(true) {
                log_msg(
                    "ERROR",
                    "USER_NODE",
                    Some(owner_id.clone()),
                    &format!("设置监听器为非阻塞失败: {}", e),
                );
                return;
            }
            loop {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _peer)) => {
                        let owner_id = owner_id.clone();
                        let broadcast_buffer = Arc::clone(&broadcast_buffer);
                        // 将连接处理派发到新线程，确保监听循环可以立即返回并处理下一个连接
                        thread::spawn(move || {
                            let mut stream = stream;
                            let res: std::io::Result<()> = (|| {
                                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                                let mut reader = BufReader::new(stream.try_clone()?);
                                let mut line = String::new();
                                reader.read_line(&mut line)?;
                                if line.trim().is_empty() {
                                    return Ok(());
                                }
                                let req: CommandRequest =
                                    serde_json::from_str(&line).unwrap_or(CommandRequest {
                                        cmd: String::new(),
                                        data: Value::Null,
                                    });
                                // 基础响应
                                let mut response = CommandResponse {
                                    ok: false,
                                    error: Some(String::from("未知命令")),
                                    extra: HashMap::new(),
                                };
                                {
                                    let mut extra = HashMap::new();
                                    extra.insert(String::from("queued"), Value::Bool(true));
                                    response.extra = extra;
                                    response.ok = true;
                                    response.error = None;
                                }
                                {
                                    let mut buffer = broadcast_buffer.lock();
                                    buffer.push_back(req.clone());
                                }
                                let resp_json = serde_json::to_string(&response).unwrap();
                                stream.write_all(resp_json.as_bytes())?;
                                stream.write_all(b"\n")?;
                                Ok(())
                            })();
                            if let Err(e) = res {
                                log_msg(
                                    "ERROR",
                                    "USER_NODE",
                                    Some(owner_id.clone()),
                                    &format!("处理连接失败: {}", e),
                                );
                            }
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // 短暂休眠，避免忙轮询
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        log_msg(
                            "ERROR",
                            "USER_NODE",
                            Some(owner_id.clone()),
                            &format!("接受连接失败: {}", e),
                        );
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            log_msg(
                "DEBUG",
                "USER_NODE",
                Some(owner_id.clone()),
                "监听线程已停止。",
            );
        });

        // 主线程：仅负责尝试发起存储与随机睡眠
        while !self.stop_flag.load(Ordering::SeqCst) {
            self.drain_broadcast_buffer();
            self.poll_blockchain_for_final_proofs();
            let should_try = {
                let active_empty = self.active_requests.lock().is_empty();
                active_empty && rand::thread_rng().gen_bool(0.3)
            };
            if should_try {
                self.try_store_file();
            }
            self.drain_broadcast_buffer();
            self.poll_blockchain_for_final_proofs();
            // 随机休眠 3~7 秒
            let ms = rand::thread_rng().gen_range(3000..=7000);
            let mut remaining = ms;
            while remaining > 0 && !self.stop_flag.load(Ordering::SeqCst) {
                let step = std::cmp::min(remaining, 500);
                thread::sleep(Duration::from_millis(step as u64));
                self.drain_broadcast_buffer();
                self.poll_blockchain_for_final_proofs();
                remaining -= step;
            }
        }
        log_msg(
            "DEBUG",
            "USER_NODE",
            Some(self.owner.owner_id.clone()),
            "进程已停止。",
        );
    }

    fn drain_broadcast_buffer(&mut self) {
        loop {
            let req_opt = {
                let mut buffer = self.broadcast_buffer.lock();
                buffer.pop_front()
            };
            let Some(req) = req_opt else {
                break;
            };
            match req.cmd.as_str() {
                "storage_bid" => {
                    let response = self.handle_storage_bid(&req.data);
                    if !response.ok {
                        // let detail = response.error.unwrap_or_else(|| String::from("未知错误"));
                        // log_msg(
                        //     "WARN",
                        //     "USER_NODE",
                        //     Some(self.owner.owner_id.clone()),
                        //     &format!("异步处理存储竞标失败: {}", detail),
                        // );
                    }
                }
                other => {
                    log_msg(
                        "DEBUG",
                        "USER_NODE",
                        Some(self.owner.owner_id.clone()),
                        &format!("收到未知广播消息 {}，已忽略", other),
                    );
                }
            }
        }
    }

    #[allow(dead_code)]
    fn handle_connection(&mut self, mut stream: TcpStream) -> std::io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() {
            return Ok(());
        }
        let req: CommandRequest = serde_json::from_str(&line).unwrap_or(CommandRequest {
            cmd: String::new(),
            data: Value::Null,
        });
        let response = self.dispatch_command(req);
        let resp_json = serde_json::to_string(&response)?;
        stream.write_all(resp_json.as_bytes())?;
        stream.write_all(b"\n")?;
        Ok(())
    }

    #[allow(dead_code)]
    fn dispatch_command(&mut self, req: CommandRequest) -> CommandResponse {
        match req.cmd.as_str() {
            "storage_bid" => self.handle_storage_bid(&req.data),
            _ => CommandResponse {
                ok: false,
                error: Some(String::from("未知命令")),
                extra: HashMap::new(),
            },
        }
    }

    #[allow(dead_code)]
    fn handle_storage_bid(&mut self, data: &Value) -> CommandResponse {
        let request_id = data.get("request_id").and_then(Value::as_str).unwrap_or("");
        let is_active = {
            let active = self.active_requests.lock();
            active.contains(request_id)
        };
        if is_active {
            {
                let mut bids_map = self.bids.lock();
                bids_map
                    .entry(request_id.to_string())
                    .or_default()
                    .push(data.clone());
            }
            CommandResponse {
                ok: true,
                error: None,
                extra: HashMap::new(),
            }
        } else {
            CommandResponse {
                ok: false,
                error: Some(String::from("请求不活跃")),
                extra: HashMap::new(),
            }
        }
    }

    fn verify_final_proof(
        stored_files: &Arc<Mutex<HashMap<String, StoredFileRecord>>>,
        owner_id: &str,
        file_id: &str,
        provider: &str,
        accumulator: &str,
        steps: usize,
        compressed_hex: &str,
        vk_hex: &str,
    ) -> Result<(), String> {
        let (record_opt, already_verified) = {
            let map = stored_files.lock();
            match map.get(file_id) {
                Some(record) => (Some(record.clone()), record.final_verified),
                None => (None, false),
            }
        };

        let record = match record_opt {
            Some(rec) => rec,
            None => return Err(String::from("参数缺失或未知文件")),
        };

        if steps != record.required_rounds {
            log_msg(
                "WARN",
                "USER_NODE",
                Some(owner_id.to_string()),
                &format!(
                    "文件 {} 的最终证明步数 {} 与期望 {} 不符。",
                    file_id, steps, record.required_rounds
                ),
            );
        }

        let compressed_bytes = match hex::decode(compressed_hex) {
            Ok(bytes) => bytes,
            Err(_) => return Err(String::from("无法解析最终证明或验证密钥")),
        };
        let vk_bytes = match hex::decode(vk_hex) {
            Ok(bytes) => bytes,
            Err(_) => return Err(String::from("无法解析最终证明或验证密钥")),
        };

        match NovaFoldingCycle::verify_final_accumulator(steps, &compressed_bytes, &vk_bytes) {
            Ok(proof_acc) => {
                if proof_acc == accumulator && steps == record.required_rounds {
                    if !already_verified {
                        log_msg(
                            "SUCCESS",
                            "USER_NODE",
                            Some(owner_id.to_string()),
                            &format!(
                                "成功验证来自节点 {} 的文件 {} 最终 Nova 证明。",
                                provider, file_id
                            ),
                        );
                        // println!(
                        //     "文件 {} 的最终 Nova 证明已成功验证（来自 {}）。",
                        //     file_id, provider
                        // );
                    }
                    {
                        let mut map = stored_files.lock();
                        if let Some(entry) = map.get_mut(file_id) {
                            entry.final_verified = true;
                        }
                    }
                    Ok(())
                } else {
                    log_msg(
                        "WARN",
                        "USER_NODE",
                        Some(owner_id.to_string()),
                        &format!(
                            "文件 {} 的最终证明通过验证但输出不匹配（acc={}, steps={})。",
                            file_id, proof_acc, steps
                        ),
                    );
                    Err(String::from("最终证明输出不匹配"))
                }
            }
            Err(err) => {
                log_msg(
                    "ERROR",
                    "USER_NODE",
                    Some(owner_id.to_string()),
                    &format!("验证文件 {} 的最终 Nova 证明失败: {}", file_id, err),
                );
                Err(String::from("最终证明验证失败"))
            }
        }
    }

    fn poll_blockchain_for_final_proofs(&mut self) {
        let pending: Vec<String> = {
            let records = self.stored_files.lock();
            records
                .iter()
                .filter_map(|(file_id, record)| {
                    if record.final_verified {
                        None
                    } else {
                        Some(file_id.clone())
                    }
                })
                .collect()
        };

        for file_id in pending {
            let payload = serde_json::json!({
                "cmd": "query_final_proof",
                "data": { "file_id": file_id },
            });

            let Some(resp_val) = super::node::send_json_line(self.bootstrap_addr, &payload) else {
                continue;
            };

            let Ok(response) = serde_json::from_value::<CommandResponse>(resp_val) else {
                continue;
            };

            if !response.ok {
                continue;
            }

            let has_final = response
                .extra
                .get("has_final_proof")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !has_final {
                continue;
            }

            let provider = response
                .extra
                .get("provider_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let Some(final_val) = response.extra.get("final_fold") else {
                continue;
            };
            if final_val.is_null() {
                continue;
            }
            let Some(final_obj) = final_val.as_object() else {
                continue;
            };

            let accumulator = match final_obj.get("accumulator").and_then(Value::as_str) {
                Some(val) if !val.is_empty() => val.to_string(),
                _ => continue,
            };
            let steps = final_obj.get("steps").and_then(Value::as_u64).unwrap_or(0) as usize;
            let compressed_hex = match final_obj.get("compressed_snark").and_then(Value::as_str) {
                Some(val) if !val.is_empty() => val.to_string(),
                _ => continue,
            };
            let vk_hex = match final_obj.get("verifier_key").and_then(Value::as_str) {
                Some(val) if !val.is_empty() => val.to_string(),
                _ => continue,
            };

            let owner_id = self.owner.owner_id.clone();
            let stored_files = Arc::clone(&self.stored_files);
            let verification = with_cpu_heavy_limit(|| {
                Self::verify_final_proof(
                    &stored_files,
                    &owner_id,
                    &file_id,
                    provider,
                    &accumulator,
                    steps,
                    &compressed_hex,
                    &vk_hex,
                )
            });

            if let Err(err) = verification {
                log_msg(
                    "WARN",
                    "USER_NODE",
                    Some(owner_id),
                    &format!("链上验证文件 {} 最终证明失败: {}", file_id, err),
                );
            }
        }
    }

    fn try_store_file(&mut self) {
        let num_nodes_required = std::cmp::min(
            rand::thread_rng()
                .gen_range(self.config.min_storage_nodes..=self.config.max_storage_nodes),
            self.config.num_nodes,
        );
        let (chunks, _) = self.owner.prepare_storage_request(
            self.config.min_file_kb * 1024,
            self.config.max_file_kb * 1024,
            num_nodes_required,
        );
        if chunks.is_empty() {
            return;
        }
        let storage_rounds = std::cmp::max(
            1,
            rand::thread_rng()
                .gen_range(self.config.min_storage_rounds..=self.config.max_storage_rounds),
        );
        let challenge_size = std::cmp::max(1, std::cmp::min(chunks.len(), 4));
        let total_size = chunks.len() * self.config.chunk_size;
        let request_id = format!("req-{}", self.owner.file_id);
        {
            let mut active = self.active_requests.lock();
            active.insert(request_id.clone());
        }
        log_msg(
            "INFO",
            "USER_NODE",
            Some(self.owner.owner_id.clone()),
            &format!(
                "为文件 {} ({}KB) 发起存储，需要 {} 个节点，要求存储 {} 轮。",
                self.owner.file_id,
                total_size / 1024,
                num_nodes_required,
                storage_rounds
            ),
        );
        let offer = serde_json::json!({
            "cmd": "inject_gossip",
            "data": {
                "type": "storage_offer",
                "request_id": request_id,
                "file_id": self.owner.file_id,
                "total_size": total_size,
                "reply_addr": [self.host, self.port],
                "storage_rounds": storage_rounds,
            }
        });
        let _ = super::node::send_json_line_without_response(self.bootstrap_addr, &offer);
        log_msg(
            "INFO",
            "USER_NODE",
            Some(self.owner.owner_id.clone()),
            &format!(
                "为请求 {} 等待 {} 秒以收集竞标...",
                request_id, self.config.bid_wait_sec
            ),
        );
        let total_wait_ms = self.config.bid_wait_sec.saturating_mul(1000);
        let mut waited_ms = 0u64;
        while waited_ms < total_wait_ms && !self.stop_flag.load(Ordering::SeqCst) {
            let remaining = total_wait_ms - waited_ms;
            let step = std::cmp::min(remaining, 200);
            thread::sleep(Duration::from_millis(step));
            self.drain_broadcast_buffer();
            waited_ms += step;
        }
        self.drain_broadcast_buffer();
        let bids = {
            let bids_map = self.bids.lock();
            bids_map.get(&request_id).cloned().unwrap_or_default()
        };
        if bids.len() >= num_nodes_required {
            let mut rng = rand::thread_rng();
            let mut winners = Vec::new();
            let mut indices: Vec<usize> = (0..bids.len()).collect();
            indices.shuffle(&mut rng);
            for idx in indices.into_iter().take(num_nodes_required) {
                winners.push(bids[idx].clone());
            }
            let addrs: Vec<SocketAddr> = winners
                .iter()
                .filter_map(|bid| {
                    let addr_arr = bid.get("bidder_addr")?.as_array()?;
                    let host = addr_arr.get(0)?.as_str()?;
                    let port = addr_arr.get(1)?.as_u64()? as u16;
                    Some(SocketAddr::new(host.parse().ok()?, port))
                })
                .collect();
            log_msg(
                "SUCCESS",
                "USER_NODE",
                Some(self.owner.owner_id.clone()),
                &format!("文件 {} 的存储竞标完成。", self.owner.file_id),
            );
            {
                let mut records = self.stored_files.lock();
                records.insert(
                    self.owner.file_id.clone(),
                    StoredFileRecord {
                        _nodes: addrs.clone(),
                        _num_chunks: chunks.len(),
                        required_rounds: storage_rounds,
                        final_verified: false,
                    },
                );
            }
            let owner_pk_beta_hex =
                hex::encode(serialize_g2(&self.owner.get_dpdp_params().pk_beta));
            for chunk in &chunks {
                let chunk_json = serde_json::to_value(chunk).unwrap();
                for addr in &addrs {
                    let data = serde_json::json!({
                        "chunk": chunk_json.clone(),
                        "owner_pk_beta": owner_pk_beta_hex,
                        "storage_period": storage_rounds,
                        "challenge_size": challenge_size,
                        "owner_addr": [self.host, self.port],
                    });
                    let payload = serde_json::json!({
                        "cmd": "chunk_distribute",
                        "data": data,
                    });
                    let _ = super::node::send_json_line(*addr, &payload);
                }
            }
            for addr in &addrs {
                let payload = serde_json::json!({"cmd": "finalize_storage", "data": {"file_id": self.owner.file_id}});
                let _ = super::node::send_json_line(*addr, &payload);
            }
        } else {
            log_msg(
                "WARN",
                "USER_NODE",
                Some(self.owner.owner_id.clone()),
                &format!("文件 {} 的存储请求失败。竞标数量不足。", self.owner.file_id),
            );
        }
        {
            let mut bids_map = self.bids.lock();
            bids_map.remove(&request_id);
        }
        {
            let mut active = self.active_requests.lock();
            active.remove(&request_id);
        }
    }
}
