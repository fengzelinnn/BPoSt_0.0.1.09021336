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

use crate::common::datastructures::FileChunk;
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
struct ProviderAssignment {
    provider_id: String,
    addr: SocketAddr,
}

#[derive(Debug, Clone)]
struct StoredFileRecord {
    chunks: Vec<FileChunk>,
    required_rounds: usize,
    challenge_size: usize,
    final_verified: bool,
    round_assignments: HashMap<usize, Vec<ProviderAssignment>>,
}

impl StoredFileRecord {
    fn provider_assigned_for_round(&self, provider_id: &str, round: usize) -> bool {
        self.round_assignments
            .get(&round)
            .map(|providers| {
                providers
                    .iter()
                    .any(|assignment| assignment.provider_id == provider_id)
            })
            .unwrap_or(false)
    }
}

struct FinalProofArgs<'a> {
    owner_id: &'a str,
    file_id: &'a str,
    provider: &'a str,
    accumulator: &'a str,
    steps: usize,
    compressed_hex: &'a str,
    vk_hex: &'a str,
}

pub struct UserNode {
    owner: FileOwner,
    host: String,
    port: u16,
    advertise_host: String,
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
        advertise_host: String,
        port: u16,
        bootstrap_addr: SocketAddr,
        config: P2PSimConfig,
    ) -> Self {
        Self {
            owner,
            host,
            advertise_host,
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
                active_empty && rand::thread_rng().gen_bool(0.1)
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
                "request_missing_chunks" => {
                    self.handle_missing_chunk_request(&req.data);
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

    fn handle_missing_chunk_request(&mut self, data: &Value) {
        let file_id = data
            .get("file_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let missing_indices: Vec<usize> = data
            .get("missing_indices")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|u| u as usize))
                    .collect()
            })
            .unwrap_or_default();
        if file_id.is_empty() || missing_indices.is_empty() {
            log_msg(
                "WARN",
                "USER_NODE",
                Some(self.owner.owner_id.clone()),
                "收到缺少必要信息的补块请求，已忽略。",
            );
            return;
        }
        let provider_id = data
            .get("provider_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let provider_addr = data
            .get("provider_addr")
            .and_then(Value::as_array)
            .and_then(|arr| {
                let host = arr.first()?.as_str()?;
                let port = arr.get(1)?.as_u64()? as u16;
                Some(SocketAddr::new(host.parse().ok()?, port))
            });

        let record_opt = {
            let records = self.stored_files.lock();
            records.get(&file_id).cloned()
        };
        let Some(record) = record_opt else {
            log_msg(
                "WARN",
                "USER_NODE",
                Some(self.owner.owner_id.clone()),
                &format!("无法响应文件 {} 的补块请求：未知的文件记录。", file_id),
            );
            return;
        };

        let target_addr = if let Some(addr) = provider_addr {
            Some(addr)
        } else {
            record
                .round_assignments
                .values()
                .flat_map(|assignments| assignments.iter())
                .find(|assignment| assignment.provider_id == provider_id)
                .map(|assignment| assignment.addr)
        };
        let Some(target_addr) = target_addr else {
            log_msg(
                "WARN",
                "USER_NODE",
                Some(self.owner.owner_id.clone()),
                &format!("无法定位请求补块的节点 {}，文件 {}。", provider_id, file_id),
            );
            return;
        };

        let owner_pk_beta_hex = hex::encode(serialize_g2(&self.owner.get_dpdp_params().pk_beta));
        let total_chunks = record.chunks.len();
        let mut resend_count = 0usize;
        for idx in &missing_indices {
            if let Some(chunk) = record.chunks.iter().find(|c| c.index == *idx) {
                let chunk_json = serde_json::to_value(chunk).unwrap_or_default();
                let data = serde_json::json!({
                    "chunk": chunk_json,
                    "owner_pk_beta": owner_pk_beta_hex,
                    "storage_period": record.required_rounds,
                    "challenge_size": record.challenge_size,
                    "owner_addr": [self.host, self.port],
                    "total_chunks": total_chunks,
                });
                let payload = serde_json::json!({
                    "cmd": "chunk_distribute",
                    "data": data,
                });
                let _ = super::node::send_json_line(target_addr, &payload);
                resend_count += 1;
            } else {
                log_msg(
                    "ERROR",
                    "USER_NODE",
                    Some(self.owner.owner_id.clone()),
                    &format!("缺失文件 {} 的第 {} 块内容，无法补发。", file_id, idx),
                );
            }
        }

        if resend_count > 0 {
            let payload = serde_json::json!({
                "cmd": "finalize_storage",
                "data": {"file_id": file_id.clone()},
            });
            let _ = super::node::send_json_line(target_addr, &payload);
            log_msg(
                "INFO",
                "USER_NODE",
                Some(self.owner.owner_id.clone()),
                &format!(
                    "已向节点 {} 重新发送文件 {} 的 {} 个缺失数据块。",
                    provider_id, file_id, resend_count
                ),
            );
        }
    }

    fn verify_final_proof(
        stored_files: &Arc<Mutex<HashMap<String, StoredFileRecord>>>,
        args: FinalProofArgs<'_>,
    ) -> Result<(), String> {
        let (record_opt, already_verified) = {
            let map = stored_files.lock();
            match map.get(args.file_id) {
                Some(record) => (Some(record.clone()), record.final_verified),
                None => (None, false),
            }
        };

        let record = match record_opt {
            Some(rec) => rec,
            None => return Err(String::from("参数缺失或未知文件")),
        };

        if !record.provider_assigned_for_round(args.provider, record.required_rounds) {
            log_msg(
                "WARN",
                "USER_NODE",
                Some(args.owner_id.to_string()),
                &format!(
                    "文件 {} 的最终证明由未在第 {} 轮登记的节点 {} 提供。",
                    args.file_id, record.required_rounds, args.provider
                ),
            );
            return Err(String::from("最终证明提供者与记录不符"));
        }

        if args.steps != record.required_rounds {
            log_msg(
                "WARN",
                "USER_NODE",
                Some(args.owner_id.to_string()),
                &format!(
                    "文件 {} 的最终证明步数 {} 与期望 {} 不符。",
                    args.file_id, args.steps, record.required_rounds
                ),
            );
        }

        let compressed_bytes = match hex::decode(args.compressed_hex) {
            Ok(bytes) => bytes,
            Err(_) => return Err(String::from("无法解析最终证明或验证密钥")),
        };
        let vk_bytes = match hex::decode(args.vk_hex) {
            Ok(bytes) => bytes,
            Err(_) => return Err(String::from("无法解析最终证明或验证密钥")),
        };

        match NovaFoldingCycle::verify_final_accumulator(args.steps, &compressed_bytes, &vk_bytes) {
            Ok(proof_acc) => {
                if proof_acc == args.accumulator && args.steps == record.required_rounds {
                    if !already_verified {
                        log_msg(
                            "INFO",
                            "!USER_NODE",
                            Some(args.owner_id.to_string()),
                            &format!(
                                "!!!!!!!成功验证来自节点 {} 的文件 {} 最终 Nova 证明。",
                                args.provider, args.file_id
                            ),
                        );
                        // println!(
                        //     "文件 {} 的最终 Nova 证明已成功验证（来自 {}）。",
                        //     file_id, provider
                        // );
                    }
                    {
                        let mut map = stored_files.lock();
                        if let Some(entry) = map.get_mut(args.file_id) {
                            entry.final_verified = true;
                        }
                    }
                    Ok(())
                } else {
                    log_msg(
                        "WARN",
                        "USER_NODE",
                        Some(args.owner_id.to_string()),
                        &format!(
                            "文件 {} 的最终证明通过验证但输出不匹配（acc={}, steps={})。",
                            args.file_id, proof_acc, args.steps
                        ),
                    );
                    Err(String::from("最终证明输出不匹配"))
                }
            }
            Err(err) => {
                log_msg(
                    "ERROR",
                    "USER_NODE",
                    Some(args.owner_id.to_string()),
                    &format!("验证文件 {} 的最终 Nova 证明失败: {}", args.file_id, err),
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
                    FinalProofArgs {
                        owner_id: &owner_id,
                        file_id: &file_id,
                        provider,
                        accumulator: &accumulator,
                        steps,
                        compressed_hex: &compressed_hex,
                        vk_hex: &vk_hex,
                    },
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
        let challenge_size = chunks.len().clamp(1, 4);
        let total_size = chunks.len() * self.config.chunk_size;
        let file_id = self.owner.file_id.clone();
        let request_id = format!("req-{}", file_id);
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
                file_id,
                total_size / 1024,
                num_nodes_required,
                storage_rounds
            ),
        );
        let offer = serde_json::json!({
            "cmd": "inject_gossip",
            "data": {
                "type": "storage_offer",
                "request_id": request_id.clone(),
                "file_id": file_id.clone(),
                "total_size": total_size,
                "reply_addr": [self.advertise_host, self.port],
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
            let provider_assignments: Vec<ProviderAssignment> = winners
                .iter()
                .filter_map(|bid| {
                    let provider_id = bid.get("bidder_id")?.as_str()?.to_string();
                    let addr_arr = bid.get("bidder_addr")?.as_array()?;
                    let host = addr_arr.first()?.as_str()?;
                    let port = addr_arr.get(1)?.as_u64()? as u16;
                    let ip = host.parse().ok()?;
                    Some(ProviderAssignment {
                        provider_id,
                        addr: SocketAddr::new(ip, port),
                    })
                })
                .collect();
            if provider_assignments.len() < num_nodes_required {
                log_msg(
                    "WARN",
                    "USER_NODE",
                    Some(self.owner.owner_id.clone()),
                    &format!(
                        "文件 {} 的竞标信息不完整，预期 {} 个节点实际有效 {} 个。",
                        file_id,
                        num_nodes_required,
                        provider_assignments.len()
                    ),
                );
            } else {
                let addrs: Vec<SocketAddr> = provider_assignments
                    .iter()
                    .map(|assignment| assignment.addr)
                    .collect();
                log_msg(
                    "SUCCESS",
                    "USER_NODE",
                    Some(self.owner.owner_id.clone()),
                    &format!("文件 {} 的存储竞标完成。", file_id),
                );
                let mut round_assignments = HashMap::new();
                for round in 1..=storage_rounds {
                    round_assignments.insert(round, provider_assignments.clone());
                }
                let mut allow_distribution = true;
                {
                    let mut records = self.stored_files.lock();
                    if records.contains_key(&file_id) {
                        log_msg(
                            "WARN",
                            "USER_NODE",
                            Some(self.owner.owner_id.clone()),
                            &format!("file_id {} 已存在，跳过覆盖旧的分发表。", file_id),
                        );
                        allow_distribution = false;
                    } else {
                        records.insert(
                            file_id.clone(),
                            StoredFileRecord {
                                chunks: chunks.clone(),
                                required_rounds: storage_rounds,
                                challenge_size,
                                final_verified: false,
                                round_assignments,
                            },
                        );
                    }
                }
                if allow_distribution {
                    let summary: Vec<String> = provider_assignments
                        .iter()
                        .map(|assignment| format!("{}@{}", assignment.provider_id, assignment.addr))
                        .collect();
                    log_msg(
                        "INFO",
                        "USER_NODE",
                        Some(self.owner.owner_id.clone()),
                        &format!(
                            "文件 {} 的分发表: 存储轮次 {}，参与者 {}。",
                            file_id,
                            storage_rounds,
                            summary.join(", ")
                        ),
                    );
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
                                "total_chunks": chunks.len(),
                            });
                            let payload = serde_json::json!({
                                "cmd": "chunk_distribute",
                                "data": data,
                            });
                            let _ = super::node::send_json_line(*addr, &payload);
                        }
                    }
                    for addr in &addrs {
                        let payload = serde_json::json!({
                            "cmd": "finalize_storage",
                            "data": {"file_id": file_id.clone()},
                        });
                        let _ = super::node::send_json_line(*addr, &payload);
                    }
                }
            }
        } else {
            log_msg(
                "WARN",
                "USER_NODE",
                Some(self.owner.owner_id.clone()),
                &format!("文件 {} 的存储请求失败。竞标数量不足。", file_id),
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
