use crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

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
struct TimedBid {
    payload: Value,
    provider_id: Option<String>,
    received_at: Instant,
}

#[derive(Debug, Default)]
struct BidQueue {
    bids: Vec<TimedBid>,
    seen_providers: HashSet<String>,
}

impl BidQueue {
    fn push(&mut self, bid: TimedBid) {
        if let Some(provider) = bid.provider_id.as_ref() {
            if !self.seen_providers.insert(provider.clone()) {
                return;
            }
        }
        self.bids.push(bid);
    }

    fn len(&self) -> usize {
        self.bids.len()
    }

    fn take(self) -> Vec<TimedBid> {
        self.bids
    }
}

#[derive(Debug, Default)]
struct BidBook {
    entries: HashMap<String, BidQueue>,
}

impl BidBook {
    fn record_bid(&mut self, request_id: &str, bid: TimedBid) -> usize {
        let queue = self
            .entries
            .entry(request_id.to_string())
            .or_insert_with(BidQueue::default);
        queue.push(bid);
        queue.len()
    }

    fn has_enough(&self, request_id: &str, required: usize) -> bool {
        self.entries
            .get(request_id)
            .map(|queue| queue.len() >= required)
            .unwrap_or(false)
    }

    fn take(&mut self, request_id: &str) -> Vec<TimedBid> {
        self.entries
            .remove(request_id)
            .map(BidQueue::take)
            .unwrap_or_default()
    }

    fn clear(&mut self, request_id: &str) {
        self.entries.remove(request_id);
    }
}

#[derive(Debug)]
enum UserEvent {
    StorageBid {
        request_id: String,
        payload: Value,
        received_at: Instant,
    },
    MissingChunks {
        payload: Value,
    },
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
    bid_book: BidBook,
    active_requests: HashSet<String>,
    stored_files: HashMap<String, StoredFileRecord>,
    known_peers: HashSet<SocketAddr>,
    force_bootstrap_target: bool,
}

impl UserNode {
    const MAX_STORAGE_BROADCAST_TARGETS: usize = 5;

    pub fn new(
        owner: FileOwner,
        host: String,
        advertise_host: String,
        port: u16,
        bootstrap_addr: SocketAddr,
        config: P2PSimConfig,
        force_bootstrap_target: bool,
    ) -> Self {
        let advertise_host = Self::resolve_advertise_host(&owner.owner_id, &host, advertise_host);
        let mut known_peers = HashSet::new();
        known_peers.insert(bootstrap_addr);
        Self {
            owner,
            host,
            advertise_host,
            port,
            bootstrap_addr,
            config,
            stop_flag: Arc::new(AtomicBool::new(false)),
            bid_book: BidBook::default(),
            active_requests: HashSet::new(),
            stored_files: HashMap::new(),
            known_peers,
            force_bootstrap_target,
        }
    }

    fn resolve_advertise_host(owner_id: &str, listen_host: &str, advertise_host: String) -> String {
        let trimmed = advertise_host.trim();
        if trimmed.is_empty() {
            log_msg(
                "WARN",
                "USER_NODE",
                Some(owner_id.to_string()),
                "未提供外部可见的地址，回退为监听地址。",
            );
            return listen_host.to_string();
        }

        match trimmed.parse::<IpAddr>() {
            Ok(ip) if ip.is_unspecified() => {
                if let Ok(listen_ip) = listen_host.parse::<IpAddr>() {
                    if !listen_ip.is_unspecified() {
                        log_msg(
                            "WARN",
                            "USER_NODE",
                            Some(owner_id.to_string()),
                            &format!(
                                "广告地址 {trimmed} 为非特定地址，回退为监听地址 {listen_ip}.",
                            ),
                        );
                        return listen_ip.to_string();
                    }
                }
                log_msg(
                    "WARN",
                    "USER_NODE",
                    Some(owner_id.to_string()),
                    &format!(
                        "广告地址 {trimmed} 为非特定地址，且监听地址 {listen_host} 同样不可用，仍将使用 {trimmed}。",
                    ),
                );
                trimmed.to_string()
            }
            Ok(ip) => ip.to_string(),
            Err(_) => trimmed.to_string(),
        }
    }

    fn parse_peer_addr_value(addr_val: &Value) -> Option<SocketAddr> {
        if let Some(arr) = addr_val.as_array() {
            if arr.len() == 2 {
                let host = arr.first()?.as_str()?;
                let port = arr.get(1)?.as_u64()? as u16;
                if let Ok(ip) = host.parse::<IpAddr>() {
                    return Some(SocketAddr::new(ip, port));
                }
                if let Ok(sock) = format!("{}:{}", host, port).parse::<SocketAddr>() {
                    return Some(sock);
                }
            }
        }
        if let Some(addr_str) = addr_val.as_str() {
            return addr_str.parse().ok();
        }
        None
    }

    fn fetch_peer_targets(&mut self) -> Vec<SocketAddr> {
        let payload = serde_json::json!({
            "cmd": "get_peers",
            "data": {},
        });
        let Some(resp_val) = super::node::send_json_line(self.bootstrap_addr, &payload) else {
            return Vec::new();
        };

        let Ok(response) = serde_json::from_value::<CommandResponse>(resp_val) else {
            return Vec::new();
        };
        if !response.ok {
            return Vec::new();
        }

        let mut addrs: Vec<SocketAddr> = Vec::new();
        let mut seen: HashSet<SocketAddr> = HashSet::new();
        if let Some(map) = response.extra.get("peers").and_then(Value::as_object) {
            for addr_val in map.values() {
                if let Some(addr) = Self::parse_peer_addr_value(addr_val) {
                    if seen.insert(addr) {
                        addrs.push(addr);
                    }
                }
            }
        }
        if !addrs.is_empty() {
            self.remember_peers(&addrs);
        }
        addrs
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

        let (event_tx, event_rx) = unbounded();
        self.spawn_accept_loop(listener, event_tx);

        let mut next_storage_attempt = Instant::now() + Self::storage_attempt_delay();
        let mut next_final_poll = Instant::now();
        let final_poll_interval = Duration::from_secs(2);

        while !self.stop_flag.load(Ordering::SeqCst) {
            self.process_events(&event_rx, Duration::from_millis(250));

            let now = Instant::now();
            if now >= next_final_poll {
                self.poll_blockchain_for_final_proofs();
                next_final_poll = now + final_poll_interval;
            }

            if self.active_requests.is_empty() && now >= next_storage_attempt {
                self.try_store_file(&event_rx);
                next_storage_attempt = Instant::now() + Self::storage_attempt_delay();
            }
        }

        log_msg(
            "DEBUG",
            "USER_NODE",
            Some(self.owner.owner_id.clone()),
            "进程已停止。",
        );
    }

    fn storage_attempt_delay() -> Duration {
        let ms = rand::thread_rng().gen_range(3000..=7000);
        Duration::from_millis(ms as u64)
    }

    fn spawn_accept_loop(&self, listener: TcpListener, event_tx: Sender<UserEvent>) {
        let stop_flag = Arc::clone(&self.stop_flag);
        let owner_id = self.owner.owner_id.clone();
        thread::spawn(move || {
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
                    Ok((stream, _)) => {
                        let owner_id = owner_id.clone();
                        let tx = event_tx.clone();
                        thread::spawn(move || {
                            Self::handle_incoming_stream(stream, tx, owner_id);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
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
    }

    fn handle_incoming_stream(
        mut stream: TcpStream,
        event_tx: Sender<UserEvent>,
        owner_id: String,
    ) {
        let res: std::io::Result<()> = (|| {
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

            let mut response = CommandResponse {
                ok: false,
                error: Some(String::from("未知命令")),
                extra: HashMap::new(),
            };
            response
                .extra
                .insert(String::from("queued"), Value::Bool(true));

            match req.cmd.as_str() {
                "storage_bid" => {
                    if let Some(request_id) = req.data.get("request_id").and_then(Value::as_str) {
                        let event = UserEvent::StorageBid {
                            request_id: request_id.to_string(),
                            payload: req.data.clone(),
                            received_at: Instant::now(),
                        };
                        if event_tx.send(event).is_ok() {
                            response.ok = true;
                            response.error = None;
                        }
                    }
                }
                "request_missing_chunks" => {
                    if event_tx
                        .send(UserEvent::MissingChunks {
                            payload: req.data.clone(),
                        })
                        .is_ok()
                    {
                        response.ok = true;
                        response.error = None;
                    }
                }
                other => {
                    log_msg(
                        "DEBUG",
                        "USER_NODE",
                        Some(owner_id.clone()),
                        &format!("收到未知广播消息 {}，已忽略", other),
                    );
                }
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
                Some(owner_id),
                &format!("处理连接失败: {}", e),
            );
        }
    }

    fn process_events(&mut self, event_rx: &Receiver<UserEvent>, timeout: Duration) {
        self.drain_pending_events(event_rx);
        if timeout.is_zero() {
            return;
        }
        let start = Instant::now();
        loop {
            if self.stop_flag.load(Ordering::SeqCst) {
                break;
            }
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                break;
            }
            let remaining = timeout.checked_sub(elapsed).unwrap_or_default();
            if remaining.is_zero() {
                break;
            }
            let wait = remaining.min(Duration::from_millis(200));
            match event_rx.recv_timeout(wait) {
                Ok(event) => {
                    self.handle_event(event);
                    self.drain_pending_events(event_rx);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn drain_pending_events(&mut self, event_rx: &Receiver<UserEvent>) {
        loop {
            match event_rx.try_recv() {
                Ok(event) => self.handle_event(event),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
            if self.stop_flag.load(Ordering::SeqCst) {
                break;
            }
        }
    }

    fn handle_event(&mut self, event: UserEvent) {
        match event {
            UserEvent::StorageBid {
                request_id,
                payload,
                received_at,
            } => self.process_storage_bid(request_id, payload, received_at),
            UserEvent::MissingChunks { payload } => self.handle_missing_chunk_request(&payload),
        }
    }

    fn process_storage_bid(&mut self, request_id: String, payload: Value, received_at: Instant) {
        if !self.active_requests.contains(&request_id) {
            return;
        }

        let provider_id = payload
            .get("bidder_id")
            .and_then(Value::as_str)
            .map(|s| s.to_string());

        let bid = TimedBid {
            payload,
            provider_id,
            received_at,
        };
        self.bid_book.record_bid(&request_id, bid);
    }

    fn wait_for_bids(
        &mut self,
        event_rx: &Receiver<UserEvent>,
        request_id: &str,
        required: usize,
        deadline: Instant,
    ) -> bool {
        while !self.stop_flag.load(Ordering::SeqCst) {
            if self.bid_book.has_enough(request_id, required) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            let now = Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                return false;
            }
            let wait = remaining.min(Duration::from_millis(200));
            match event_rx.recv_timeout(wait) {
                Ok(event) => {
                    self.handle_event(event);
                    self.drain_pending_events(event_rx);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return false,
            }
        }
        false
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

        let Some(record) = self.stored_files.get(&file_id).cloned() else {
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
        record: &StoredFileRecord,
        already_verified: bool,
        args: FinalProofArgs<'_>,
    ) -> Result<(), String> {
        if record.chunks.is_empty() {
            return Err(String::from("参数缺失或未知文件"));
        }

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
        let pending: Vec<String> = self
            .stored_files
            .iter()
            .filter_map(|(file_id, record)| (!record.final_verified).then(|| file_id.clone()))
            .collect();

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

            let Some(record) = self.stored_files.get(&file_id).cloned() else {
                continue;
            };
            let owner_id = self.owner.owner_id.clone();
            let verification = with_cpu_heavy_limit(|| {
                Self::verify_final_proof(
                    &record,
                    record.final_verified,
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

            match verification {
                Ok(()) => {
                    if let Some(entry) = self.stored_files.get_mut(&file_id) {
                        entry.final_verified = true;
                    }
                }
                Err(err) => {
                    log_msg(
                        "WARN",
                        "USER_NODE",
                        Some(owner_id),
                        &format!("链上验证文件 {} 最终证明失败: {}", file_id, err),
                    );
                }
            }
        }
    }

    fn try_store_file(&mut self, event_rx: &Receiver<UserEvent>) {
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
        self.active_requests.insert(request_id.clone());
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
                "reply_addr": [self.advertise_host.clone(), self.port],
                "storage_rounds": storage_rounds,
            }
        });
        let wait_duration = Duration::from_secs(self.config.bid_wait_sec.max(1));
        log_msg(
            "INFO",
            "USER_NODE",
            Some(self.owner.owner_id.clone()),
            &format!(
                "为请求 {} 最多等待 {} 秒以收集竞标...",
                request_id,
                wait_duration.as_secs()
            ),
        );

        let max_attempts = 3usize;
        let mut attempt = 0usize;
        let mut reached_capacity = false;
        let mut collected_bids: Vec<TimedBid> = Vec::new();

        while attempt < max_attempts && !self.stop_flag.load(Ordering::SeqCst) {
            let fanout = Self::MAX_STORAGE_BROADCAST_TARGETS + attempt * 2;
            self.broadcast_storage_offer(&offer, fanout);
            if attempt > 0 {
                log_msg(
                    "DEBUG",
                    "USER_NODE",
                    Some(self.owner.owner_id.clone()),
                    &format!("请求 {} 触发第 {} 次扩散广播。", request_id, attempt + 1),
                );
            }

            let deadline = Instant::now() + wait_duration;
            if self.wait_for_bids(event_rx, &request_id, num_nodes_required, deadline) {
                reached_capacity = true;
            }

            if self.bid_book.has_enough(&request_id, num_nodes_required) {
                collected_bids = self.bid_book.take(&request_id);
                break;
            }

            attempt += 1;
            if attempt >= max_attempts {
                collected_bids = self.bid_book.take(&request_id);
                break;
            }

            let newly_found = self.fetch_peer_targets();
            if !newly_found.is_empty() {
                log_msg(
                    "DEBUG",
                    "USER_NODE",
                    Some(self.owner.owner_id.clone()),
                    &format!(
                        "请求 {} 未收集到足够竞标，新增 {} 个候选节点。",
                        request_id,
                        newly_found.len()
                    ),
                );
            }
        }

        if collected_bids.len() >= num_nodes_required {
            if reached_capacity {
                log_msg(
                    "DEBUG",
                    "USER_NODE",
                    Some(self.owner.owner_id.clone()),
                    &format!(
                        "请求 {} 在 {} 秒内收到了足够的竞标。",
                        request_id,
                        wait_duration.as_secs()
                    ),
                );
            }
            let mut ordered_bids = collected_bids;
            ordered_bids.sort_by_key(|bid| bid.received_at);
            let provider_assignments: Vec<ProviderAssignment> = ordered_bids
                .iter()
                .take(num_nodes_required)
                .filter_map(|bid| {
                    let provider_id = bid.provider_id.clone().or_else(|| {
                        bid.payload
                            .get("bidder_id")
                            .and_then(Value::as_str)
                            .map(|s| s.to_string())
                    })?;
                    let addr_arr = bid.payload.get("bidder_addr")?.as_array()?;
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
                log_msg(
                    "SUCCESS",
                    "USER_NODE",
                    Some(self.owner.owner_id.clone()),
                    &format!("文件 {} 的存储竞标完成。", file_id),
                );
                let owner_pk_beta_hex =
                    hex::encode(serialize_g2(&self.owner.get_dpdp_params().pk_beta));
                let allow_distribution = if self.stored_files.contains_key(&file_id) {
                    log_msg(
                        "WARN",
                        "USER_NODE",
                        Some(self.owner.owner_id.clone()),
                        &format!("file_id {} 已存在，跳过覆盖旧的分发表。", file_id),
                    );
                    false
                } else {
                    true
                };
                if allow_distribution {
                    let mut successful_assignments = self.distribute_file_to_providers(
                        &file_id,
                        &chunks,
                        &provider_assignments,
                        &owner_pk_beta_hex,
                        storage_rounds,
                        challenge_size,
                    );
                    let mut finalize_attempted = false;
                    if successful_assignments.is_empty() {
                        log_msg(
                            "ERROR",
                            "USER_NODE",
                            Some(self.owner.owner_id.clone()),
                            &format!("文件 {} 的分发失败，所有目标节点均未确认存储。", file_id),
                        );
                    } else {
                        let chunk_summary: Vec<String> = successful_assignments
                            .iter()
                            .map(|assignment| {
                                format!("{}@{}", assignment.provider_id, assignment.addr)
                            })
                            .collect();
                        log_msg(
                            "INFO",
                            "USER_NODE",
                            Some(self.owner.owner_id.clone()),
                            &format!(
                                "文件 {} 的分发表: 存储轮次 {}，确认节点 {}。",
                                file_id,
                                storage_rounds,
                                chunk_summary.join(", ")
                            ),
                        );
                        if successful_assignments.len() < num_nodes_required {
                            let addrs: Vec<SocketAddr> =
                                successful_assignments.iter().map(|a| a.addr).collect();
                            if !addrs.is_empty() {
                                self.remember_peers(&addrs);
                            }
                            log_msg(
                                "WARN",
                                "USER_NODE",
                                Some(self.owner.owner_id.clone()),
                                &format!(
                                    "文件 {} 实际确认节点 {} 个，低于预期的 {} 个。",
                                    file_id,
                                    successful_assignments.len(),
                                    num_nodes_required
                                ),
                            );
                            log_msg(
                                "INFO",
                                "USER_NODE",
                                Some(self.owner.owner_id.clone()),
                                &format!(
                                    "文件 {} 未达到确认阈值，跳过 finalize_storage 操作。",
                                    file_id
                                ),
                            );
                        }
                        if successful_assignments.len() >= num_nodes_required {
                            let finalized_assignments = self
                                .finalize_storage_for_providers(&file_id, &successful_assignments);
                            finalize_attempted = true;
                            if finalized_assignments.len() < successful_assignments.len() {
                                log_msg(
                                    "WARN",
                                    "USER_NODE",
                                    Some(self.owner.owner_id.clone()),
                                    &format!(
                                        "文件 {} 有 {} 个节点在 finalize 阶段失败。",
                                        file_id,
                                        successful_assignments.len() - finalized_assignments.len()
                                    ),
                                );
                            }
                            successful_assignments = finalized_assignments;
                        }
                        if successful_assignments.len() >= num_nodes_required {
                            let final_summary: Vec<String> = successful_assignments
                                .iter()
                                .map(|assignment| {
                                    format!("{}@{}", assignment.provider_id, assignment.addr)
                                })
                                .collect();
                            log_msg(
                                "INFO",
                                "USER_NODE",
                                Some(self.owner.owner_id.clone()),
                                &format!(
                                    "文件 {} finalize 完成: 存储轮次 {}，最终节点 {}。",
                                    file_id,
                                    storage_rounds,
                                    final_summary.join(", ")
                                ),
                            );
                            let addrs: Vec<SocketAddr> =
                                successful_assignments.iter().map(|a| a.addr).collect();
                            if !addrs.is_empty() {
                                self.remember_peers(&addrs);
                            }
                            let mut round_assignments = HashMap::new();
                            for round in 1..=storage_rounds {
                                round_assignments.insert(round, successful_assignments.clone());
                            }
                            let record = StoredFileRecord {
                                chunks: chunks.clone(),
                                required_rounds: storage_rounds,
                                challenge_size,
                                final_verified: false,
                                round_assignments,
                            };
                            self.stored_files.insert(file_id.clone(), record);
                        } else if finalize_attempted
                            && successful_assignments.len() < num_nodes_required
                        {
                            log_msg(
                                "WARN",
                                "USER_NODE",
                                Some(self.owner.owner_id.clone()),
                                &format!(
                                    "文件 {} finalize 后确认节点 {} 个，低于预期的 {} 个。",
                                    file_id,
                                    successful_assignments.len(),
                                    num_nodes_required
                                ),
                            );
                        }
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
        self.bid_book.clear(&request_id);
        self.active_requests.remove(&request_id);
    }
}

impl UserNode {
    fn collect_known_peers(&self) -> Vec<SocketAddr> {
        self.known_peers.iter().copied().collect()
    }

    fn broadcast_storage_offer(&mut self, offer: &Value, fanout: usize) {
        if self.known_peers.len() < fanout {
            let _ = self.fetch_peer_targets();
        }
        if self.known_peers.is_empty() {
            self.known_peers.insert(self.bootstrap_addr);
        }
        let mut targets = self.collect_known_peers();
        if targets.is_empty() {
            targets.push(self.bootstrap_addr);
        }
        targets.shuffle(&mut rand::thread_rng());
        let max_targets = fanout.max(1);
        let mut selected: Vec<SocketAddr> = targets.into_iter().take(max_targets).collect();
        self.ensure_bootstrap_target(&mut selected, max_targets);
        if selected.is_empty() {
            selected.push(self.bootstrap_addr);
        }
        for target in selected {
            let _ = super::node::send_json_line_without_response(target, offer);
        }
    }

    fn distribute_file_to_providers(
        &self,
        file_id: &str,
        chunks: &[FileChunk],
        assignments: &[ProviderAssignment],
        owner_pk_beta_hex: &str,
        storage_rounds: usize,
        challenge_size: usize,
    ) -> Vec<ProviderAssignment> {
        if assignments.is_empty() {
            return Vec::new();
        }

        let chunk_values: Vec<Value> = chunks
            .iter()
            .map(|chunk| serde_json::to_value(chunk).unwrap())
            .collect();
        let total_chunks = chunks.len();
        let owner_addr_value = serde_json::json!([self.advertise_host.clone(), self.port]);

        let mut provider_success = vec![true; assignments.len()];
        let mut provider_errors: Vec<Vec<String>> = vec![Vec::new(); assignments.len()];

        let mut chunk_requests = Vec::new();
        let mut chunk_meta = Vec::new();
        for (provider_idx, assignment) in assignments.iter().enumerate() {
            for (chunk_idx, chunk_json) in chunk_values.iter().enumerate() {
                let data = serde_json::json!({
                    "chunk": chunk_json.clone(),
                    "owner_pk_beta": owner_pk_beta_hex,
                    "storage_period": storage_rounds,
                    "challenge_size": challenge_size,
                    "owner_addr": owner_addr_value.clone(),
                    "total_chunks": total_chunks,
                });
                let payload = serde_json::json!({
                    "cmd": "chunk_distribute",
                    "data": data,
                });
                chunk_requests.push((assignment.addr, payload));
                chunk_meta.push((provider_idx, chunk_idx));
            }
        }

        if !chunk_requests.is_empty() {
            let responses = super::node::send_json_lines_parallel(chunk_requests);
            for ((provider_idx, chunk_idx), response) in
                chunk_meta.into_iter().zip(responses.into_iter())
            {
                if provider_success[provider_idx] {
                    match response {
                        Some(value) => match serde_json::from_value::<CommandResponse>(value) {
                            Ok(resp) if resp.ok => {}
                            Ok(resp) => {
                                provider_success[provider_idx] = false;
                                let reason = resp.error.unwrap_or_else(|| "未知错误".to_string());
                                provider_errors[provider_idx]
                                    .push(format!("chunk {}: {}", chunk_idx, reason));
                            }
                            Err(err) => {
                                provider_success[provider_idx] = false;
                                provider_errors[provider_idx]
                                    .push(format!("chunk {}: 响应解析失败 {}", chunk_idx, err));
                            }
                        },
                        None => {
                            provider_success[provider_idx] = false;
                            provider_errors[provider_idx]
                                .push(format!("chunk {}: 无响应", chunk_idx));
                        }
                    }
                }
            }
        }

        let mut successes = Vec::new();
        for (idx, assignment) in assignments.iter().enumerate() {
            if provider_success[idx] {
                successes.push(assignment.clone());
            } else {
                let reason = if provider_errors[idx].is_empty() {
                    String::from("未知原因")
                } else {
                    provider_errors[idx].join("; ")
                };
                log_msg(
                    "WARN",
                    "USER_NODE",
                    Some(self.owner.owner_id.clone()),
                    &format!(
                        "分发文件 {} 至节点 {}@{} 失败: {}",
                        file_id, assignment.provider_id, assignment.addr, reason
                    ),
                );
            }
        }

        successes
    }

    fn finalize_storage_for_providers(
        &self,
        file_id: &str,
        assignments: &[ProviderAssignment],
    ) -> Vec<ProviderAssignment> {
        if assignments.is_empty() {
            return Vec::new();
        }

        let finalize_requests: Vec<(SocketAddr, Value)> = assignments
            .iter()
            .map(|assignment| {
                let payload = serde_json::json!({
                    "cmd": "finalize_storage",
                    "data": {"file_id": file_id},
                });
                (assignment.addr, payload)
            })
            .collect();

        let responses = super::node::send_json_lines_parallel(finalize_requests);
        let mut successes = Vec::new();

        for (assignment, response) in assignments.iter().cloned().zip(responses.into_iter()) {
            match response {
                Some(value) => match serde_json::from_value::<CommandResponse>(value) {
                    Ok(resp) if resp.ok => {
                        successes.push(assignment);
                    }
                    Ok(resp) => {
                        let reason = resp.error.unwrap_or_else(|| "未知错误".to_string());
                        log_msg(
                            "WARN",
                            "USER_NODE",
                            Some(self.owner.owner_id.clone()),
                            &format!(
                                "文件 {} 在 finalize 阶段确认节点 {}@{} 失败: {}",
                                file_id, assignment.provider_id, assignment.addr, reason
                            ),
                        );
                    }
                    Err(err) => {
                        log_msg(
                            "WARN",
                            "USER_NODE",
                            Some(self.owner.owner_id.clone()),
                            &format!(
                                "文件 {} finalize 响应解析失败 {} 来自节点 {}@{}",
                                file_id, err, assignment.provider_id, assignment.addr
                            ),
                        );
                    }
                },
                None => {
                    log_msg(
                        "WARN",
                        "USER_NODE",
                        Some(self.owner.owner_id.clone()),
                        &format!(
                            "文件 {} finalize 阶段节点 {}@{} 无响应",
                            file_id, assignment.provider_id, assignment.addr
                        ),
                    );
                }
            }
        }

        successes
    }

    fn remember_peers(&mut self, peers: &[SocketAddr]) {
        for addr in peers {
            self.known_peers.insert(*addr);
        }
    }

    fn ensure_bootstrap_target(&self, selected: &mut Vec<SocketAddr>, max_targets: usize) {
        if !self.force_bootstrap_target {
            return;
        }
        if selected.iter().any(|addr| *addr == self.bootstrap_addr) {
            return;
        }
        if max_targets > 0 && selected.len() >= max_targets {
            selected.pop();
        }
        selected.push(self.bootstrap_addr);
    }
}
