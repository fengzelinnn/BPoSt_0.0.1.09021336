use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::unbounded;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::utils::log_msg;

use super::node::{send_json_line, send_json_line_without_response};

/// 观察者节点接收到的消息条目。
#[derive(Debug, Clone)]
struct ObservedMessage {
    received_at: Instant,
    msg_type: String,
    duplicate: bool,
}

/// 观察者用于统计的快照信息。
#[derive(Debug, Clone, Default)]
struct ObserverSnapshot {
    blocks: usize,
    proofs: usize,
    orders: usize,
    messages: usize,
}

/// 自上次报告以来的增量统计。
#[derive(Debug, Clone, Default)]
struct ObserverDelta {
    new_blocks: usize,
    new_proofs: usize,
    new_orders: usize,
    new_messages: usize,
}

/// 观察者节点内部维护的统计数据。
struct ObserverMetrics {
    start_time: Instant,
    last_block_time: Option<Instant>,
    last_proof_time: Option<Instant>,
    block_intervals: Vec<f64>,
    proof_intervals: Vec<f64>,
    total_blocks: usize,
    total_proofs: usize,
    total_orders: usize,
    total_messages: usize,
    message_counts: HashMap<String, usize>,
    last_report: Option<ObserverSnapshot>,
}

impl ObserverMetrics {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            last_block_time: None,
            last_proof_time: None,
            block_intervals: Vec::new(),
            proof_intervals: Vec::new(),
            total_blocks: 0,
            total_proofs: 0,
            total_orders: 0,
            total_messages: 0,
            message_counts: HashMap::new(),
            last_report: None,
        }
    }

    fn record_message(&mut self, msg_type: &str, timestamp: Instant, count_for_stats: bool) {
        self.total_messages += 1;
        *self.message_counts.entry(msg_type.to_string()).or_insert(0) += 1;

        if !count_for_stats {
            return;
        }

        match msg_type {
            "new_block" => self.record_block(timestamp),
            "bobtail_proof" => self.record_proof(timestamp),
            "storage_offer" => self.total_orders += 1,
            _ => {}
        }
    }

    fn record_block(&mut self, timestamp: Instant) {
        if let Some(prev) = self.last_block_time {
            self.block_intervals
                .push(timestamp.duration_since(prev).as_secs_f64());
        }
        self.last_block_time = Some(timestamp);
        self.total_blocks += 1;
    }

    fn record_proof(&mut self, timestamp: Instant) {
        if let Some(prev) = self.last_proof_time {
            self.proof_intervals
                .push(timestamp.duration_since(prev).as_secs_f64());
        }
        self.last_proof_time = Some(timestamp);
        self.total_proofs += 1;
    }

    fn block_stats(&self) -> Option<(f64, f64)> {
        mean_and_variance(&self.block_intervals)
    }

    fn proof_stats(&self) -> Option<(f64, f64)> {
        mean_and_variance(&self.proof_intervals)
    }

    fn diff_since_last_report(&mut self) -> ObserverDelta {
        let current = ObserverSnapshot {
            blocks: self.total_blocks,
            proofs: self.total_proofs,
            orders: self.total_orders,
            messages: self.total_messages,
        };
        let delta = if let Some(last) = &self.last_report {
            ObserverDelta {
                new_blocks: current.blocks.saturating_sub(last.blocks),
                new_proofs: current.proofs.saturating_sub(last.proofs),
                new_orders: current.orders.saturating_sub(last.orders),
                new_messages: current.messages.saturating_sub(last.messages),
            }
        } else {
            ObserverDelta {
                new_blocks: current.blocks,
                new_proofs: current.proofs,
                new_orders: current.orders,
                new_messages: current.messages,
            }
        };
        self.last_report = Some(current);
        delta
    }

    fn top_message_types(&self, limit: usize) -> Vec<(String, usize)> {
        let mut pairs: Vec<(String, usize)> = self
            .message_counts
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        pairs.truncate(limit);
        pairs
    }

    fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}

fn mean_and_variance(samples: &[f64]) -> Option<(f64, f64)> {
    if samples.is_empty() {
        return None;
    }
    let len = samples.len() as f64;
    let mean = samples.iter().sum::<f64>() / len;
    let variance = samples
        .iter()
        .map(|value| {
            let diff = value - mean;
            diff * diff
        })
        .sum::<f64>()
        / len;
    Some((mean, variance))
}

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

/// 共识观察者节点。
pub struct ObserverNode {
    observer_id: String,
    host: String,
    port: u16,
    bootstrap_addr: SocketAddr,
    peers: HashMap<String, SocketAddr>,
    stop_flag: Arc<AtomicBool>,
    gossip_buffer: VecDeque<ObservedMessage>,
    seen_gossip_ids: HashSet<String>,
    metrics: ObserverMetrics,
    report_interval: Duration,
}

impl ObserverNode {
    const MAX_BUFFER_SIZE: usize = 500_000;

    pub fn new(
        observer_id: String,
        host: String,
        port: u16,
        bootstrap_addr: SocketAddr,
        report_interval: Duration,
    ) -> Self {
        Self {
            observer_id,
            host,
            port,
            bootstrap_addr,
            peers: HashMap::new(),
            stop_flag: Arc::new(AtomicBool::new(false)),
            gossip_buffer: VecDeque::with_capacity(Self::MAX_BUFFER_SIZE.min(10_000)),
            seen_gossip_ids: HashSet::new(),
            metrics: ObserverMetrics::new(),
            report_interval,
        }
    }

    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    pub fn run(mut self) {
        let addr = SocketAddr::new(self.host.parse().unwrap(), self.port);
        let listener = match TcpListener::bind(addr) {
            Ok(l) => {
                log_msg(
                    "INFO",
                    "OBSERVER",
                    Some(self.observer_id.clone()),
                    &format!("观察者节点已在 {}:{} 启动", self.host, self.port),
                );
                l
            }
            Err(e) => {
                log_msg(
                    "CRITICAL",
                    "OBSERVER",
                    Some(self.observer_id.clone()),
                    &format!("无法启动观察者监听器: {}", e),
                );
                return;
            }
        };
        if let Err(e) = listener.set_nonblocking(true) {
            log_msg(
                "ERROR",
                "OBSERVER",
                Some(self.observer_id.clone()),
                &format!("设置监听器为非阻塞失败: {}", e),
            );
            return;
        }

        let (conn_tx, conn_rx) = unbounded::<TcpStream>();
        let listener_stop = Arc::clone(&self.stop_flag);
        let observer_id = self.observer_id.clone();
        let accept_handle = thread::spawn(move || loop {
            if listener_stop.load(Ordering::SeqCst) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    if conn_tx.send(stream).is_err() {
                        break;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(err) => {
                    log_msg(
                        "WARN",
                        "OBSERVER",
                        Some(observer_id.clone()),
                        &format!("接受连接失败: {}", err),
                    );
                    thread::sleep(Duration::from_millis(200));
                }
            }
        });

        self.discover_peers();

        let mut next_report = Instant::now() + self.report_interval;
        while !self.stop_flag.load(Ordering::SeqCst) {
            match conn_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(stream) => {
                    if let Err(err) = self.handle_connection(stream) {
                        if !matches!(
                            err.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                        ) {
                            log_msg(
                                "ERROR",
                                "OBSERVER",
                                Some(self.observer_id.clone()),
                                &format!("处理连接失败: {}", err),
                            );
                        }
                    }
                }
                Err(_) => {}
            }

            if Instant::now() >= next_report {
                self.report_metrics();
                next_report += self.report_interval;
            }
        }

        drop(conn_rx);
        let _ = accept_handle.join();
        log_msg(
            "INFO",
            "OBSERVER",
            Some(self.observer_id.clone()),
            "观察者节点停止。",
        );
    }

    fn handle_connection(&mut self, stream: TcpStream) -> std::io::Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
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
        let mut writer = stream;
        let resp_json = serde_json::to_string(&response)?;
        writer.write_all(resp_json.as_bytes())?;
        writer.write_all(b"\n")?;
        Ok(())
    }

    fn dispatch_command(&mut self, req: CommandRequest) -> CommandResponse {
        match req.cmd.as_str() {
            "get_peers" => self.handle_get_peers(),
            "announce" => {
                if let Some((node_id, addr)) = parse_announce(&req.data) {
                    if node_id != self.observer_id {
                        self.peers.insert(node_id, addr);
                    }
                }
                CommandResponse {
                    ok: true,
                    error: None,
                    extra: HashMap::new(),
                }
            }
            "gossip" | "inject_gossip" => {
                self.handle_gossip(&req.data);
                CommandResponse {
                    ok: true,
                    error: None,
                    extra: HashMap::new(),
                }
            }
            _ => CommandResponse {
                ok: false,
                error: Some(String::from("未知命令")),
                extra: HashMap::new(),
            },
        }
    }

    fn handle_get_peers(&self) -> CommandResponse {
        let mut peers_obj: Map<String, Value> = Map::new();
        peers_obj.insert(
            self.observer_id.clone(),
            serde_json::json!([self.host.clone(), self.port]),
        );
        for (node_id, addr) in &self.peers {
            if node_id == &self.observer_id {
                continue;
            }
            peers_obj.insert(
                node_id.clone(),
                serde_json::json!([addr.ip().to_string(), addr.port()]),
            );
        }
        let mut extra = HashMap::new();
        extra.insert(String::from("peers"), Value::Object(peers_obj));
        CommandResponse {
            ok: true,
            error: None,
            extra,
        }
    }

    fn handle_gossip(&mut self, data: &Value) {
        let now = Instant::now();
        let msg_type = data
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let mut is_new = true;
        if let Some(gossip_id) = data.get("gossip_id").and_then(Value::as_str) {
            if !self.seen_gossip_ids.insert(gossip_id.to_string()) {
                is_new = false;
            }
        }
        self.record_buffer_entry(msg_type.clone(), now, !is_new);
        self.metrics.record_message(&msg_type, now, is_new);
    }

    fn record_buffer_entry(&mut self, msg_type: String, timestamp: Instant, duplicate: bool) {
        if self.gossip_buffer.len() >= Self::MAX_BUFFER_SIZE {
            self.gossip_buffer.pop_front();
        }
        self.gossip_buffer.push_back(ObservedMessage {
            received_at: timestamp,
            msg_type,
            duplicate,
        });
    }

    fn report_metrics(&mut self) {
        let delta = self.metrics.diff_since_last_report();
        let block_stats = self.metrics.block_stats();
        let proof_stats = self.metrics.proof_stats();
        let block_summary = match block_stats {
            Some((avg, var)) => format!("平均 {:.2}s, 方差 {:.2}", avg, var),
            None => String::from("暂无数据"),
        };
        let proof_summary = match proof_stats {
            Some((avg, var)) => format!("平均 {:.2}s, 方差 {:.2}", avg, var),
            None => String::from("暂无数据"),
        };
        let buffer_size = self.gossip_buffer.len();
        let duplicate_count = self
            .gossip_buffer
            .iter()
            .filter(|msg| msg.duplicate)
            .count();
        let buffer_summary = if let Some(msg) = self.gossip_buffer.back() {
            let age = msg.received_at.elapsed().as_secs_f64();
            format!(
                "缓存占用 {}/{}, 重复 {} 条，最近消息 {} {:.2}s 前",
                buffer_size,
                Self::MAX_BUFFER_SIZE,
                duplicate_count,
                msg.msg_type,
                age
            )
        } else {
            format!(
                "缓存占用 {}/{}, 暂无消息",
                buffer_size,
                Self::MAX_BUFFER_SIZE
            )
        };
        let top_types = self
            .metrics
            .top_message_types(3)
            .into_iter()
            .map(|(ty, count)| format!("{}:{}", ty, count))
            .collect::<Vec<_>>()
            .join(", ");
        let uptime = self.metrics.uptime().as_secs();
        let summary = format!(
            "观察窗口({}s): 新消息 {} 条, 新区块 {} 个, 新证明 {} 个, 新订单 {} 个。累计消息 {} 条, 区块 {} 个, 证明 {} 个, 订单 {} 个。出块间隔 {}, 证明间隔 {}。运行时长 {}s。类型分布: {}。{}",
            self.report_interval.as_secs(),
            delta.new_messages,
            delta.new_blocks,
            delta.new_proofs,
            delta.new_orders,
            self.metrics.total_messages,
            self.metrics.total_blocks,
            self.metrics.total_proofs,
            self.metrics.total_orders,
            block_summary,
            proof_summary,
            uptime,
            if top_types.is_empty() {
                String::from("无")
            } else {
                top_types
            },
            buffer_summary
        );
        log_msg("INFO", "OBSERVER", Some(self.observer_id.clone()), &summary);
    }

    fn discover_peers(&mut self) {
        log_msg(
            "INFO",
            "OBSERVER",
            Some(self.observer_id.clone()),
            &format!(
                "观察者节点正在通过引导节点 {} 发现网络对等体",
                self.bootstrap_addr
            ),
        );

        let announce_payload = serde_json::json!({
            "cmd": "announce",
            "data": {
                "node_id": self.observer_id,
                "host": self.host,
                "port": self.port,
            }
        });
        let _ = send_json_line_without_response(self.bootstrap_addr, &announce_payload);

        if let Some(resp) = send_json_line(
            self.bootstrap_addr,
            &serde_json::json!({"cmd": "get_peers", "data": {}}),
        ) {
            if resp.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                if let Some(map) = resp.get("peers").and_then(Value::as_object) {
                    for (node_id, addr_val) in map {
                        if let Some(addr) = parse_peer_addr(addr_val) {
                            if node_id != &self.observer_id {
                                self.peers.insert(node_id.clone(), addr);
                                self.notify_peer(addr);
                            }
                        }
                    }
                }
            }
        }
    }

    fn notify_peer(&self, addr: SocketAddr) {
        let payload = serde_json::json!({
            "cmd": "announce",
            "data": {
                "node_id": self.observer_id,
                "host": self.host,
                "port": self.port,
            }
        });
        let _ = send_json_line_without_response(addr, &payload);
    }
}

fn parse_peer_addr(val: &Value) -> Option<SocketAddr> {
    let arr = val.as_array()?;
    if arr.len() != 2 {
        return None;
    }
    let host = arr.first()?.as_str()?;
    let port = arr.get(1)?.as_u64()? as u16;
    Some(SocketAddr::new(host.parse().ok()?, port))
}

fn parse_announce(data: &Value) -> Option<(String, SocketAddr)> {
    let node_id = data.get("node_id")?.as_str()?.to_string();
    let host = data.get("host")?.as_str()?;
    let port = data.get("port")?.as_u64()? as u16;
    Some((node_id, SocketAddr::new(host.parse().ok()?, port)))
}
