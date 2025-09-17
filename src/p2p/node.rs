use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use num_bigint::BigUint;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;

use crate::common::datastructures::{
    Block, BlockBody, BobtailProof, ChallengeEntry, DPDPParams, DPDPProof, FileChunk, ProofSummary,
};
use crate::consensus::blockchain::Blockchain;
use crate::crypto::deserialize_g2;
use crate::crypto::dpdp::DPDP;
use crate::roles::miner::Miner;
use crate::roles::prover::Prover;
use crate::storage::manager::StorageManager;
use crate::utils::{build_merkle_tree, log_msg};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeReport {
    pub node_id: String,
    pub chain_height: usize,
    pub chain_head: String,
    pub peers: usize,
    pub mempool_size: usize,
    pub proof_pool_size: usize,
    pub is_mining: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RoundUpdate {
    file_roots: HashMap<String, String>,
    challenges: HashMap<String, Vec<ChallengeEntry>>,
    dpdp_proofs: HashMap<String, Value>,
}

pub struct Node {
    pub node_id: String,
    host: String,
    port: u16,
    bootstrap_addr: Option<SocketAddr>,
    storage_manager: StorageManager,
    prover: Prover,
    miner: Miner,
    peers: HashMap<String, SocketAddr>,
    mempool: VecDeque<Value>,
    proof_pool: HashMap<usize, HashMap<String, BobtailProof>>,
    seen_gossip_ids: HashSet<String>,
    chain: Blockchain,
    bobtail_k: usize,
    prepare_margin: usize,
    difficulty_threshold: BigUint,
    preprepare_signals: HashMap<usize, HashMap<String, Vec<String>>>,
    sent_preprepare_signal_at: HashMap<usize, Vec<String>>,
    election_concluded_for: HashSet<usize>,
    round_tst_updates: HashMap<usize, HashMap<String, RoundUpdate>>,
    stop_flag: Arc<AtomicBool>,
    report_sender: Sender<NodeReport>,
}

impl Node {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: String,
        host: String,
        port: u16,
        bootstrap_addr: Option<SocketAddr>,
        chunk_size: usize,
        max_storage: usize,
        bobtail_k: usize,
        report_sender: Sender<NodeReport>,
    ) -> Self {
        let difficulty_threshold = BigUint::parse_bytes(
            b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            16,
        )
        .unwrap();
        Self {
            storage_manager: StorageManager::new(node_id.clone(), chunk_size, max_storage),
            prover: Prover::new(node_id.clone()),
            miner: Miner::new(node_id.clone(), format!("addr:{}", node_id)),
            node_id,
            host,
            port,
            bootstrap_addr,
            peers: HashMap::new(),
            mempool: VecDeque::new(),
            proof_pool: HashMap::new(),
            seen_gossip_ids: HashSet::new(),
            chain: Blockchain::new(),
            bobtail_k,
            prepare_margin: 0,
            difficulty_threshold,
            preprepare_signals: HashMap::new(),
            sent_preprepare_signal_at: HashMap::new(),
            election_concluded_for: HashSet::new(),
            round_tst_updates: HashMap::new(),
            stop_flag: Arc::new(AtomicBool::new(false)),
            report_sender,
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
                    "P2P_NET",
                    Some(self.node_id.clone()),
                    &format!("在 {}:{} 上监听", self.host, self.port),
                );
                l
            }
            Err(e) => {
                log_msg(
                    "CRITICAL",
                    "P2P_NET",
                    Some(self.node_id.clone()),
                    &format!("启动服务器失败: {}", e),
                );
                return;
            }
        };
        listener.set_nonblocking(true).expect("set nonblocking");
        self.discover_peers();
        log_msg(
            "DEBUG",
            "NODE",
            Some(self.node_id.clone()),
            &format!("进入主循环..."),
        );
        let mut last_report = Instant::now();
        let mut last_consensus = Instant::now();
        while !self.stop_flag.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Err(e) = self.handle_connection(stream) {
                        log_msg(
                            "ERROR",
                            "NODE",
                            Some(self.node_id.clone()),
                            &format!("处理连接失败: {}", e),
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    log_msg(
                        "ERROR",
                        "P2P_NET",
                        Some(self.node_id.clone()),
                        &format!("接受连接失败: {}", e),
                    );
                }
            }

            if !self.mempool.is_empty() {
                self.process_mempool();
            }

            if last_consensus.elapsed()
                > Duration::from_millis(rand::thread_rng().gen_range(1000..2000))
            {
                self.attempt_consensus();
                last_consensus = Instant::now();
            }

            if last_report.elapsed() > Duration::from_secs(3) {
                self.report_status();
                last_report = Instant::now();
            }

            if self.mempool.is_empty() {
                thread::sleep(Duration::from_millis(100));
            }
        }
        log_msg("DEBUG", "NODE", Some(self.node_id.clone()), "节点停止。");
    }

    fn report_status(&self) {
        let height = self.chain.height();
        let proof_pool_size = self
            .proof_pool
            .get(&(height + 1))
            .map(|m| m.len())
            .unwrap_or(0);
        let report = NodeReport {
            node_id: self.node_id.clone(),
            chain_height: height,
            chain_head: self.chain.last_hash(),
            peers: self.peers.len(),
            mempool_size: self.mempool.len(),
            proof_pool_size,
            is_mining: self.storage_manager.get_num_files() > 0,
        };
        let _ = self.report_sender.send(report);
    }

    fn handle_connection(&mut self, stream: TcpStream) -> std::io::Result<()> {
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
        let mut writer = stream;
        let resp_json = serde_json::to_string(&response).unwrap();
        writer.write_all(resp_json.as_bytes())?;
        writer.write_all(b"\n")?;
        Ok(())
    }

    fn dispatch_command(&mut self, req: CommandRequest) -> CommandResponse {
        match req.cmd.as_str() {
            "get_peers" => {
                let mut peers_obj: Map<String, Value> = Map::new();
                peers_obj.insert(
                    self.node_id.clone(),
                    serde_json::json!([self.host.clone(), self.port]),
                );
                for (k, v) in &self.peers {
                    if k == &self.node_id {
                        continue;
                    }
                    let entry = serde_json::json!([v.ip().to_string(), v.port()]);
                    peers_obj.insert(k.clone(), entry);
                }

                let mut extra = HashMap::new();
                extra.insert(String::from("peers"), Value::Object(peers_obj));
                CommandResponse {
                    ok: true,
                    error: None,
                    extra,
                }
            }
            "announce" => {
                if let Some((node_id, addr)) = parse_announce(&req.data) {
                    if node_id != self.node_id {
                        self.peers.insert(node_id, addr);
                    }
                }
                CommandResponse {
                    ok: true,
                    error: None,
                    extra: HashMap::new(),
                }
            }
            "gossip" => {
                self.handle_gossip(&req.data);
                CommandResponse {
                    ok: true,
                    error: None,
                    extra: HashMap::new(),
                }
            }
            "inject_gossip" => {
                self.gossip(req.data, true);
                CommandResponse {
                    ok: true,
                    error: None,
                    extra: HashMap::new(),
                }
            }
            "chunk_distribute" => self.handle_chunk_distribute(&req.data),
            "finalize_storage" => {
                self.storage_manager.finalize_commitments();
                CommandResponse {
                    ok: true,
                    error: None,
                    extra: HashMap::new(),
                }
            }
            "dpdp_challenge" => self.handle_dpdp_challenge(&req.data),
            _ => CommandResponse {
                ok: false,
                error: Some(String::from("未知命令")),
                extra: HashMap::new(),
            },
        }
    }

    fn handle_chunk_distribute(&mut self, data: &Value) -> CommandResponse {
        let chunk_val = data.get("chunk").cloned().unwrap_or(Value::Null);
        let chunk: FileChunk = match serde_json::from_value(chunk_val) {
            Ok(c) => c,
            Err(e) => {
                return CommandResponse {
                    ok: false,
                    error: Some(format!("无效的chunk: {}", e)),
                    extra: HashMap::new(),
                };
            }
        };
        let ok = self.storage_manager.receive_chunk(&chunk);
        if let Some(pk_hex) = data.get("owner_pk_beta").and_then(Value::as_str) {
            let pk_bytes = hex::decode(pk_hex).unwrap_or_default();
            if !pk_bytes.is_empty() {
                self.storage_manager
                    .set_file_pk_beta(&chunk.file_id, pk_bytes);
            }
        }
        CommandResponse {
            ok,
            error: None,
            extra: HashMap::new(),
        }
    }

    fn handle_dpdp_challenge(&mut self, data: &Value) -> CommandResponse {
        let file_id = data.get("file_id").and_then(Value::as_str).unwrap_or("");
        let indices: Vec<usize> = data
            .get("indices")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_u64().map(|u| u as usize))
                    .collect()
            })
            .unwrap_or_default();
        if file_id.is_empty() || indices.is_empty() {
            return CommandResponse {
                ok: false,
                error: Some(String::from("缺少参数")),
                extra: HashMap::new(),
            };
        }
        let prev_hash = self.chain.last_hash();
        let timestamp = self
            .chain
            .blocks
            .last()
            .map(|b| (b.timestamp / 1_000_000_000) as u64)
            .unwrap_or_else(|| chrono::Utc::now().timestamp() as u64);
        let (chunks, tags) = self.storage_manager.get_file_data_for_proof(file_id);
        let (proof, challenge, contributions) = self
            .prover
            .prove(file_id, &indices, &chunks, &tags, &prev_hash, timestamp);
        self.storage_manager.update_state_after_contributions(
            file_id,
            &contributions,
            &format!("{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        );
        log_msg(
            "INFO",
            "dPDP_PROVE",
            Some(self.node_id.clone()),
            &format!("为文件 {} 生成了dPDP证明。", file_id),
        );
        let challenge_json: Vec<Value> = challenge
            .iter()
            .map(|(i, v)| serde_json::json!([*i as u64, v.to_string()]))
            .collect();
        let mut extra = HashMap::new();
        extra.insert(String::from("proof"), serde_json::to_value(&proof).unwrap());
        extra.insert(String::from("challenge"), Value::from(challenge_json));
        CommandResponse {
            ok: true,
            error: None,
            extra,
        }
    }

    fn discover_peers(&mut self) {
        if let Some(bootstrap) = self.bootstrap_addr {
            log_msg(
                "DEBUG",
                "P2P_DISCOVERY",
                Some(self.node_id.clone()),
                &format!("联系引导节点 {}...", bootstrap),
            );
            let _ = send_json_line(
                bootstrap,
                &serde_json::json!({
                    "cmd": "announce",
                    "data": {
                        "node_id": self.node_id,
                        "host": self.host,
                        "port": self.port,
                    }
                }),
            );
            if let Some(resp) = send_json_line(
                bootstrap,
                &serde_json::json!({"cmd": "get_peers", "data": {}}),
            ) {
                if resp.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                    if let Some(map) = resp.get("peers").and_then(Value::as_object) {
                        for (nid, addr_val) in map {
                            if nid == &self.node_id {
                                continue;
                            }
                            if let Some(addr_arr) = addr_val.as_array() {
                                if addr_arr.len() == 2 {
                                    if let (Some(host), Some(port)) = (
                                        addr_arr.get(0).and_then(Value::as_str),
                                        addr_arr.get(1).and_then(Value::as_u64),
                                    ) {
                                        if let Ok(ip) = host.parse() {
                                            let addr = SocketAddr::new(ip, port as u16);
                                            self.peers.insert(nid.clone(), addr);
                                            continue;
                                        }
                                    }
                                }
                            }

                            if let Some(addr_str) = addr_val.as_str() {
                                if let Ok(addr) = addr_str.parse() {
                                    self.peers.insert(nid.clone(), addr);
                                }
                            }
                        }
                    }
                }
            }
            log_msg(
                "INFO",
                "P2P_DISCOVERY",
                Some(self.node_id.clone()),
                &format!("发现了 {} 个初始对等节点。", self.peers.len()),
            );
        } else {
            log_msg(
                "DEBUG",
                "P2P_DISCOVERY",
                Some(self.node_id.clone()),
                "作为引导节点运行。",
            );
        }
    }

    fn handle_gossip(&mut self, data: &Value) {
        if let Some(gossip_id) = data.get("gossip_id").and_then(Value::as_str) {
            if self.seen_gossip_ids.contains(gossip_id) {
                return;
            }
            self.seen_gossip_ids.insert(gossip_id.to_string());
        }
        if let Some(msg_type) = data.get("type").and_then(Value::as_str) {
            match msg_type {
                "storage_offer" => {
                    if let Some(total_size) = data.get("total_size").and_then(Value::as_u64) {
                        if self.storage_manager.can_store(total_size as usize) {
                            if let Some(reply) = data.get("reply_addr").and_then(|v| v.as_array()) {
                                if reply.len() == 2 {
                                    if let (Some(host), Some(port)) =
                                        (reply[0].as_str(), reply[1].as_u64())
                                    {
                                        let request_id = data
                                            .get("request_id")
                                            .and_then(Value::as_str)
                                            .unwrap_or("");
                                        let payload = serde_json::json!({
                                            "cmd": "storage_bid",
                                            "data": {
                                                "type": "storage_bid",
                                                "request_id": request_id,
                                                "bidder_id": self.node_id,
                                                "bidder_addr": [self.host, self.port],
                                            }
                                        });
                                        let addr =
                                            SocketAddr::new(host.parse().unwrap(), port as u16);
                                        let _ = send_json_line(addr, &payload);
                                    }
                                }
                            }
                        }
                    }
                }
                "bobtail_proof" | "preprepare_sync" | "new_block" => {
                    self.mempool.push_back(data.clone());
                }
                "tst_update" => {
                    if let Some(height) = data.get("height").and_then(Value::as_u64) {
                        if let Some(node_id) = data.get("node_id").and_then(Value::as_str) {
                            let file_roots = data
                                .get("file_roots")
                                .cloned()
                                .unwrap_or_else(|| Value::Object(Default::default()));
                            let challenges = data
                                .get("challenges")
                                .cloned()
                                .unwrap_or_else(|| Value::Object(Default::default()));
                            let dpdp_proofs = data
                                .get("dpdp_proofs")
                                .cloned()
                                .unwrap_or_else(|| Value::Object(Default::default()));
                            let update = RoundUpdate {
                                file_roots: serde_json::from_value(file_roots).unwrap_or_default(),
                                challenges: serde_json::from_value(challenges).unwrap_or_default(),
                                dpdp_proofs: serde_json::from_value(dpdp_proofs)
                                    .unwrap_or_default(),
                            };
                            self.round_tst_updates
                                .entry(height as usize)
                                .or_default()
                                .insert(node_id.to_string(), update);
                        }
                    }
                }
                _ => {}
            }
        }
        self.gossip(data.clone(), false);
    }

    fn gossip(&mut self, mut message: Value, originator: bool) {
        if originator {
            let gid = format!(
                "{}:{}",
                self.node_id,
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            );
            if let Value::Object(map) = &mut message {
                map.insert(String::from("gossip_id"), Value::from(gid.clone()));
            }
            self.seen_gossip_ids.insert(gid);
        }
        for addr in self.peers.values() {
            if let Some(resp) = send_json_line(
                *addr,
                &serde_json::json!({"cmd": "gossip", "data": message}),
            ) {
                let _ = resp;
            }
        }
    }

    fn process_mempool(&mut self) {
        let next_height = self.chain.height() + 1;
        if let Some(pos) = self.mempool.iter().position(|msg| {
            msg.get("type").and_then(Value::as_str) == Some("new_block")
                && msg
                    .get("height")
                    .and_then(Value::as_u64)
                    .map(|h| h as usize)
                    == Some(next_height)
        }) {
            if let Some(msg) = self.mempool.remove(pos) {
                if let Some(block_val) = msg.get("block") {
                    if let Ok(block) = serde_json::from_value::<Block>(block_val.clone()) {
                        if block.prev_hash == self.chain.last_hash() {
                            self.chain.add_block(block.clone(), None);
                            log_msg(
                                "INFO",
                                "BLOCKCHAIN",
                                Some(self.node_id.clone()),
                                &format!("接受了来自 {} 的区块 {}", block.leader_id, block.height),
                            );
                            self.perform_dpdp_round(&block);
                            self.proof_pool.remove(&next_height);
                            self.preprepare_signals.remove(&next_height);
                            self.sent_preprepare_signal_at.remove(&next_height);
                            self.election_concluded_for.insert(next_height);
                        }
                    }
                }
            }
            return;
        }
        if let Some(msg) = self.mempool.pop_front() {
            let height = msg
                .get("height")
                .and_then(Value::as_u64)
                .map(|h| h as usize)
                .unwrap_or(0);
            if height < self.chain.height() + 1 || self.election_concluded_for.contains(&height) {
                return;
            }
            match msg.get("type").and_then(Value::as_str) {
                Some("bobtail_proof") => {
                    if let Some(proof_val) = msg.get("proof") {
                        if let Ok(proof) = serde_json::from_value::<BobtailProof>(proof_val.clone())
                        {
                            self.proof_pool
                                .entry(height)
                                .or_default()
                                .entry(proof.node_id.clone())
                                .or_insert(proof);
                        }
                    }
                }
                Some("preprepare_sync") => {
                    if let Some(signals) = msg.get("signals").and_then(Value::as_object) {
                        let entry = self.preprepare_signals.entry(height).or_default();
                        for (sender, list_val) in signals {
                            if let Some(list) = list_val.as_array() {
                                let hashes: Vec<String> = list
                                    .iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect();
                                entry.entry(sender.clone()).or_insert(hashes);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn attempt_consensus(&mut self) {
        if self.storage_manager.get_num_files() == 0 {
            return;
        }
        let height = self.chain.height() + 1;
        if self.election_concluded_for.contains(&height) {
            return;
        }
        if !self
            .proof_pool
            .get(&height)
            .map(|m| m.contains_key(&self.node_id))
            .unwrap_or(false)
        {
            let seed = self.chain.last_hash();
            let proofs = self.miner.mine(
                &seed,
                &self.storage_manager.get_storage_root(),
                &self.storage_manager.get_file_roots(),
                self.storage_manager.get_num_files(),
                10_000,
            );
            if let Some(proof) = proofs.first() {
                self.proof_pool
                    .entry(height)
                    .or_default()
                    .entry(self.node_id.clone())
                    .or_insert(proof.clone());
                log_msg(
                    "DEBUG",
                    "CONSENSUS",
                    Some(self.node_id.clone()),
                    &format!("为高度 {} 挖出了一个证明", height),
                );
                self.gossip(
                    serde_json::json!({
                        "type": "bobtail_proof",
                        "height": height,
                        "proof": proof,
                    }),
                    true,
                );
            }
        }
        self.try_elect_leader(height);
    }

    fn try_elect_leader(&mut self, height: usize) {
        if self.election_concluded_for.contains(&height) {
            return;
        }
        if !self.sent_preprepare_signal_at.contains_key(&height) {
            let mut proofs: Vec<BobtailProof> = self
                .proof_pool
                .get(&height)
                .map(|m| m.values().cloned().collect())
                .unwrap_or_default();
            if proofs.len() >= self.bobtail_k + self.prepare_margin {
                proofs.sort_by(|a, b| a.proof_hash.cmp(&b.proof_hash));
                let selected = proofs[..self.bobtail_k].to_vec();
                let avg_hash = selected
                    .iter()
                    .map(|p| BigUint::parse_bytes(p.proof_hash.as_bytes(), 16).unwrap_or_default())
                    .fold(BigUint::from(0u32), |acc, x| acc + x)
                    / BigUint::from(self.bobtail_k as u32);
                if avg_hash <= self.difficulty_threshold {
                    let proof_hashes: Vec<String> =
                        selected.iter().map(|p| p.proof_hash.clone()).collect();
                    self.sent_preprepare_signal_at
                        .insert(height, proof_hashes.clone());
                    self.preprepare_signals
                        .entry(height)
                        .or_default()
                        .insert(self.node_id.clone(), proof_hashes);
                    log_msg(
                        "INFO",
                        "CONSENSUS",
                        Some(self.node_id.clone()),
                        &format!("为高度 {} 达成预备条件，创建自己的提案。", height),
                    );
                }
            }
        }
        if let Some(signals_snapshot) = self.preprepare_signals.get(&height).cloned() {
            self.gossip(
                serde_json::json!({
                    "type": "preprepare_sync",
                    "height": height,
                    "sender_id": self.node_id,
                    "signals": signals_snapshot,
                }),
                true,
            );
            let mut votes: HashMap<Vec<String>, Vec<String>> = HashMap::new();
            for (sender, proof_hashes) in &signals_snapshot {
                votes
                    .entry(proof_hashes.clone())
                    .or_default()
                    .push(sender.clone());
            }
            for (proof_set, voters) in votes {
                if voters.len() >= self.bobtail_k {
                    log_msg(
                        "INFO",
                        "CONSENSUS",
                        Some(self.node_id.clone()),
                        &format!(
                            "高度 {} 的共识达成 (提案有 {} 票)，开始选举领导者。",
                            height,
                            voters.len()
                        ),
                    );
                    let known: HashSet<String> = self
                        .proof_pool
                        .get(&height)
                        .map(|m| m.values().map(|p| p.proof_hash.clone()).collect())
                        .unwrap_or_default();
                    if !proof_set.iter().all(|hash| known.contains(hash)) {
                        log_msg(
                            "WARN",
                            "CONSENSUS",
                            Some(self.node_id.clone()),
                            &format!("缺少获胜集合中的证明，等待同步..."),
                        );
                        continue;
                    }
                    let mut winning: Vec<BobtailProof> = self
                        .proof_pool
                        .get(&height)
                        .map(|m| {
                            m.values()
                                .filter(|p| proof_set.contains(&p.proof_hash))
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default();
                    if winning.len() < self.bobtail_k {
                        continue;
                    }
                    winning.sort_by(|a, b| a.proof_hash.cmp(&b.proof_hash));
                    let leader_id = winning[0].node_id.clone();
                    if leader_id == self.node_id {
                        self.create_block(height, winning);
                    }
                    self.election_concluded_for.insert(height);
                    return;
                }
            }
        }
    }

    fn create_block(&mut self, height: usize, winning_proofs: Vec<BobtailProof>) {
        log_msg(
            "SUCCESS",
            "CONSENSUS",
            Some(self.node_id.clone()),
            &format!("被选举为高度 {} 的领导者！正在创建区块...", height),
        );
        let proof_hashes: Vec<String> = winning_proofs
            .iter()
            .map(|p| p.proof_hash.clone())
            .collect();
        let (proofs_merkle_root, proofs_merkle_tree) = build_merkle_tree(&proof_hashes);
        let prev_height = height - 1;
        let updates_for_prev = self
            .round_tst_updates
            .get(&prev_height)
            .cloned()
            .unwrap_or_default();
        let winners_ids: Vec<String> = winning_proofs.iter().map(|p| p.node_id.clone()).collect();
        let mut winners_roots = HashMap::new();
        let mut dpdp_challenges: HashMap<String, HashMap<String, Vec<ChallengeEntry>>> =
            HashMap::new();
        let mut dpdp_proofs = HashMap::new();
        for nid in &winners_ids {
            if let Some(update) = updates_for_prev.get(nid) {
                winners_roots.insert(nid.clone(), update.file_roots.clone());
                dpdp_challenges.insert(nid.clone(), update.challenges.clone());
                dpdp_proofs.insert(nid.clone(), update.dpdp_proofs.clone());
            }
        }
        for nid in &winners_ids {
            if let Some(update) = updates_for_prev.get(nid) {
                for (fid, pkg_val) in &update.dpdp_proofs {
                    if let Some(pkg_obj) = pkg_val.as_object() {
                        let proof_val = pkg_obj.get("proof").cloned().unwrap_or(Value::Null);
                        let challenge_val =
                            pkg_obj.get("challenge").cloned().unwrap_or(Value::Null);
                        let pk_hex = pkg_obj.get("pk_beta").and_then(Value::as_str).unwrap_or("");
                        if pk_hex.is_empty() {
                            log_msg(
                                "ERROR",
                                "CONSENSUS",
                                Some(self.node_id.clone()),
                                &format!("节点 {} 文件 {} 缺少 pk_beta，放弃本次出块。", nid, fid),
                            );
                            return;
                        }
                        let proof = match serde_json::from_value::<DPDPProof>(proof_val) {
                            Ok(p) => p,
                            Err(e) => {
                                log_msg(
                                    "ERROR",
                                    "CONSENSUS",
                                    Some(self.node_id.clone()),
                                    &format!(
                                        "dPDP 证明解析失败：节点 {} 文件 {} 错误 {}",
                                        nid, fid, e
                                    ),
                                );
                                return;
                            }
                        };
                        let challenge: Vec<(usize, BigUint)> = challenge_val
                            .as_array()
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|entry| match entry.as_array() {
                                        Some(inner) if inner.len() == 2 => Some((
                                            inner[0].as_u64().unwrap_or(0) as usize,
                                            BigUint::parse_bytes(
                                                inner[1].as_str().unwrap_or("0").as_bytes(),
                                                10,
                                            )
                                            .unwrap_or_default(),
                                        )),
                                        _ => None,
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        let pk_bytes = match hex::decode(pk_hex) {
                            Ok(bytes) if bytes.len() == 192 => bytes,
                            _ => {
                                log_msg(
                                    "ERROR",
                                    "CONSENSUS",
                                    Some(self.node_id.clone()),
                                    &format!(
                                        "节点 {} 文件 {} 的 pk_beta 无法解析，放弃本次出块。",
                                        nid, fid
                                    ),
                                );
                                return;
                            }
                        };
                        let params = DPDPParams {
                            g: G2Affine::generator().into(),
                            u: G1Affine::generator().into(),
                            pk_beta: deserialize_g2(&pk_bytes),
                            sk_alpha: BigUint::from(0u32),
                        };
                        if !DPDP::check_proof(&params, &proof, &challenge) {
                            log_msg(
                                "CRITICAL",
                                "CONSENSUS",
                                Some(self.node_id.clone()),
                                &format!(
                                    "dPDP 证明验证失败：节点 {} 文件 {}，放弃本次出块。",
                                    nid, fid
                                ),
                            );
                            return;
                        }
                    }
                }
            }
        }
        let body = BlockBody {
            selected_k_proofs: winning_proofs
                .iter()
                .map(|p| ProofSummary {
                    node_id: p.node_id.clone(),
                    proof_hash: p.proof_hash.clone(),
                })
                .collect(),
            coinbase_splits: winning_proofs
                .iter()
                .map(|p| (p.address.clone(), String::from("1")))
                .collect(),
            proofs_merkle_tree: proofs_merkle_tree,
            dpdp_challenges,
        };
        let new_block = Block {
            height: height as u64,
            prev_hash: self.chain.last_hash(),
            seed: self.chain.last_hash(),
            leader_id: self.node_id.clone(),
            accum_proof_hash: String::from("placeholder"),
            merkle_roots: HashMap::from([(String::from("proofs_merkle_root"), proofs_merkle_root)]),
            round_proof_stmt_hash: String::from("placeholder"),
            body,
            time_tree_roots: winners_roots,
            bobtail_k: self.bobtail_k as u64,
            bobtail_target: format!("{:x}", self.difficulty_threshold),
            timestamp: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
        };
        self.gossip(
            serde_json::json!({
                "type": "new_block",
                "height": height,
                "block": new_block,
            }),
            true,
        );
    }

    fn perform_dpdp_round(&mut self, accepted_block: &Block) {
        if self.storage_manager.get_num_files() == 0 {
            return;
        }
        let round_salt = format!("{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
        let mut challenges_by_file: HashMap<String, Vec<ChallengeEntry>> = HashMap::new();
        let mut dpdp_proofs_by_file: HashMap<String, Value> = HashMap::new();
        let file_ids = self.storage_manager.list_file_ids();
        for fid in &file_ids {
            let (chunks, tags) = self.storage_manager.get_file_data_for_proof(fid);
            let (proof, challenge, contributions) = self.prover.prove(
                fid,
                &[],
                &chunks,
                &tags,
                &accepted_block.prev_hash,
                (accepted_block.timestamp / 1_000_000_000) as u64,
            );
            self.storage_manager
                .update_state_after_contributions(fid, &contributions, &round_salt);
            let entries: Vec<ChallengeEntry> = challenge
                .iter()
                .map(|(i, v)| ChallengeEntry(*i, v.to_string()))
                .collect();
            challenges_by_file.insert(fid.clone(), entries);
            let pk_hex = self
                .storage_manager
                .get_file_pk_beta(fid)
                .map(|bytes| hex::encode(bytes))
                .unwrap_or_default();
            let challenge_json: Vec<Value> = challenge
                .iter()
                .map(|(i, v)| serde_json::json!([*i as u64, v.to_string()]))
                .collect();
            dpdp_proofs_by_file.insert(
                fid.clone(),
                serde_json::json!({
                    "proof": proof,
                    "challenge": challenge_json,
                    "pk_beta": pk_hex,
                }),
            );
        }
        let roots = self.storage_manager.get_file_roots();
        let challenges_copy = challenges_by_file.clone();
        let proofs_copy = dpdp_proofs_by_file.clone();
        let msg = serde_json::json!({
            "type": "tst_update",
            "height": accepted_block.height,
            "node_id": self.node_id,
            "file_roots": roots,
            "challenges": challenges_by_file,
            "dpdp_proofs": dpdp_proofs_by_file,
        });
        self.gossip(msg.clone(), true);
        let update = RoundUpdate {
            file_roots: self.storage_manager.get_file_roots(),
            challenges: challenges_copy,
            dpdp_proofs: proofs_copy,
        };
        self.round_tst_updates
            .entry(accepted_block.height as usize)
            .or_default()
            .insert(self.node_id.clone(), update);
    }
}

fn parse_announce(data: &Value) -> Option<(String, SocketAddr)> {
    let node_id = data.get("node_id")?.as_str()?.to_string();
    let host = data.get("host")?.as_str()?;
    let port = data.get("port")?.as_u64()? as u16;
    Some((node_id, SocketAddr::new(host.parse().ok()?, port)))
}

pub fn send_json_line(addr: SocketAddr, payload: &Value) -> Option<Value> {
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(1500)) {
        let json = serde_json::to_string(payload).ok()?;
        let _ = stream.write_all(json.as_bytes());
        let _ = stream.write_all(b"\n");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? > 0 {
            serde_json::from_str(&line).ok()
        } else {
            None
        }
    } else {
        None
    }
}
