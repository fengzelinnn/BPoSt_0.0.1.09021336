use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::P2PSimConfig;
use crate::crypto::serialize_g2;
use crate::roles::file_owner::FileOwner;
use crate::utils::log_msg;

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

pub struct UserNode {
    owner: FileOwner,
    host: String,
    port: u16,
    bootstrap_addr: SocketAddr,
    config: P2PSimConfig,
    stop_flag: Arc<AtomicBool>,
    bids: HashMap<String, Vec<Value>>,
    active_requests: HashSet<String>,
    stored_files: HashMap<String, (Vec<SocketAddr>, usize)>,
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
            bids: HashMap::new(),
            active_requests: HashSet::new(),
            stored_files: HashMap::new(),
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
        listener.set_nonblocking(true).unwrap();
        log_msg(
            "INFO",
            "USER_NODE",
            Some(self.owner.owner_id.clone()),
            &format!("用户节点已在 {}:{} 启动", self.host, self.port),
        );
        let mut last_action = Instant::now();
        while !self.stop_flag.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = self.handle_connection(stream);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    log_msg(
                        "ERROR",
                        "USER_NODE",
                        Some(self.owner.owner_id.clone()),
                        &format!("接受连接失败: {}", e),
                    );
                }
            }
            if last_action.elapsed() > Duration::from_secs(3) {
                if self.active_requests.is_empty() && rand::thread_rng().gen_bool(0.3) {
                    self.try_store_file();
                }
                last_action = Instant::now();
            }
            thread::sleep(Duration::from_millis(200));
        }
        log_msg(
            "DEBUG",
            "USER_NODE",
            Some(self.owner.owner_id.clone()),
            "进程已停止。",
        );
    }

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
        let resp_json = serde_json::to_string(&response).unwrap();
        stream.write_all(resp_json.as_bytes())?;
        stream.write_all(b"\n")?;
        Ok(())
    }

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

    fn handle_storage_bid(&mut self, data: &Value) -> CommandResponse {
        let request_id = data.get("request_id").and_then(Value::as_str).unwrap_or("");
        if self.active_requests.contains(request_id) {
            self.bids
                .entry(request_id.to_string())
                .or_default()
                .push(data.clone());
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
        let total_size = chunks.len() * self.config.chunk_size;
        let request_id = format!("req-{}", self.owner.file_id);
        self.active_requests.insert(request_id.clone());
        log_msg(
            "INFO",
            "USER_NODE",
            Some(self.owner.owner_id.clone()),
            &format!(
                "为文件 {} ({}KB) 发起存储，需要 {} 个节点。",
                self.owner.file_id,
                total_size / 1024,
                num_nodes_required
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
        thread::sleep(Duration::from_secs(self.config.bid_wait_sec));
        let bids = self.bids.get(&request_id).cloned().unwrap_or_default();
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
            self.stored_files
                .insert(self.owner.file_id.clone(), (addrs.clone(), chunks.len()));
            let owner_pk_beta_hex =
                hex::encode(serialize_g2(&self.owner.get_dpdp_params().pk_beta));
            for chunk in &chunks {
                let chunk_json = serde_json::to_value(chunk).unwrap();
                for addr in &addrs {
                    let payload = serde_json::json!({
                        "cmd": "chunk_distribute",
                        "data": {
                            "chunk": chunk_json.clone(),
                            "owner_pk_beta": owner_pk_beta_hex,
                        }
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
        self.bids.remove(&request_id);
        self.active_requests.remove(&request_id);
    }
}
