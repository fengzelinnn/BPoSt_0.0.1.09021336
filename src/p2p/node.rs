use std::collections::{HashMap, HashSet, VecDeque}; // 集合类型
use std::io::{BufRead, BufReader, Write}; // IO 操作
use std::net::{SocketAddr, TcpListener, TcpStream}; // 网络地址和TCP流
use std::sync::atomic::{AtomicBool, Ordering}; // 原子布尔值，用于线程安全地停止节点
use std::sync::Arc; // 原子引用计数，用于多线程共享数据
use std::thread; // 线程操作
use std::time::{Duration, Instant}; // 时间相关操作

use crossbeam_channel::{unbounded, RecvTimeoutError, Sender}; // 高性能的并发消息通道
use num_bigint::BigUint; // 大整数处理
use rand::Rng; // 随机数生成
use serde::{Deserialize, Serialize}; // 序列化和反序列化
use serde_json::{Map, Value}; // JSON处理

use ark_bn254::{G1Affine, G2Affine}; // BN254椭圆曲线上的点
use ark_ec::AffineRepr; // 椭圆曲线点的仿射表示

// 导入项目内部模块
use crate::common::datastructures::{
    Block, BlockBody, BobtailProof, ChallengeEntry, DPDPParams, DPDPProof, FileChunk, ProofSummary,
}; // 数据结构
use crate::consensus::blockchain::Blockchain; // 区块链逻辑
use crate::crypto::deserialize_g2; // G2点反序列化工具
use crate::crypto::dpdp::DPDP; // dPDP 密码学逻辑
use crate::roles::miner::Miner; // 矿工角色
use crate::roles::prover::Prover; // 证明者角色
use crate::storage::manager::StorageManager; // 存储管理器
use crate::utils::{build_merkle_tree, log_msg}; // 工具函数

/// 节点状态报告结构体，用于向外部报告节点的当前状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeReport {
    pub node_id: String,        // 节点ID
    pub chain_height: usize,    // 当前区块链高度
    pub chain_head: String,     // 当前链头哈希
    pub peers: usize,           // 连接的对等节点数量
    pub mempool_size: usize,    // 内存池中的消息数量
    pub proof_pool_size: usize, // 证明池中的证明数量
    pub is_mining: bool,        // 是否正在挖矿（即是否存储了文件）
}

/// 节点间直接通信的命令请求结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommandRequest {
    cmd: String, // 命令名称
    #[serde(default)]
    data: Value, // 命令附带的数据
}

/// 节点间直接通信的命令响应结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommandResponse {
    ok: bool, // 命令是否成功执行
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>, // 如果失败，附带的错误信息
    #[serde(flatten)]
    extra: HashMap<String, Value>, // 额外的响应数据
}

/// 共识轮次更新的数据结构，用于在节点间同步状态
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RoundUpdate {
    file_roots: HashMap<String, String>, // 文件根哈希的集合
    challenges: HashMap<String, Vec<ChallengeEntry>>, // dPDP挑战的集合
    dpdp_proofs: HashMap<String, Value>, // dPDP证明的集合
}

/// P2P网络中的核心节点结构体
pub struct Node {
    pub node_id: String,                                       // 节点的唯一标识符
    host: String,                                              // 节点监听的主机地址
    port: u16,                                                 // 节点监听的端口
    bootstrap_addr: Option<SocketAddr>, // 引导节点的地址，如果没有则自己是引导节点
    storage_manager: StorageManager,    // 存储管理器，负责文件的存储和检索
    prover: Prover,                     // 证明者，负责生成dPDP证明
    miner: Miner,                       // 矿工，负责挖矿（生成Bobtail证明）
    peers: HashMap<String, SocketAddr>, // 对等节点列表 <node_id, addr>
    mempool: VecDeque<Value>,           // 内存池，暂存待处理的gossip消息
    proof_pool: HashMap<usize, HashMap<String, BobtailProof>>, // 证明池 <height, <node_id, proof>>
    seen_gossip_ids: HashSet<String>,   // 已见过的gossip消息ID，防止重复处理
    chain: Blockchain,                  // 节点的区块链实例
    bobtail_k: usize,                   // Bobtail共识算法中的k参数
    prepare_margin: usize,              // 预备阶段的容错边际
    difficulty_threshold: BigUint,      // 挖矿难度阈值
    preprepare_signals: HashMap<usize, HashMap<String, Vec<String>>>, // 预备信号 <height, <sender_id, proof_hashes>>
    sent_preprepare_signal_at: HashMap<usize, Vec<String>>, // 记录在某个高度已发送的预备信号
    election_concluded_for: HashSet<usize>,                 // 记录已完成领导者选举的高度
    round_tst_updates: HashMap<usize, HashMap<String, RoundUpdate>>, // 轮次状态更新 <height, <node_id, update>>
    stop_flag: Arc<AtomicBool>,                                      // 优雅停机的标志
    report_sender: Sender<NodeReport>,                               // 用于发送节点状态报告的通道
}

impl Node {
    /// 创建一个新的Node实例
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
        // 初始化挖矿难度阈值
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

    /// 获取节点的停止句柄，用于从外部停止节点
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    /// 运行节点的主循环
    pub fn run(mut self) {
        let addr = SocketAddr::new(self.host.parse().unwrap(), self.port);
        // 绑定TCP监听器
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
        // 设置为非阻塞模式
        listener.set_nonblocking(true).expect("set nonblocking");

        // 创建一个通道用于从监听线程接收新的TCP连接
        let (conn_tx, conn_rx) = unbounded::<TcpStream>();
        let listener_stop = Arc::clone(&self.stop_flag);
        let node_id_for_thread = self.node_id.clone();

        // 启动一个独立的线程来接受TCP连接
        let listener_handle = thread::spawn(move || {
            loop {
                if listener_stop.load(Ordering::SeqCst) {
                    break; // 如果收到停止信号，则退出循环
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        // 接受新连接并发送到主线程处理
                        if conn_tx.send(stream).is_err() {
                            break; // 如果通道关闭，则退出
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // 非阻塞模式下没有新连接，短暂休眠
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => {
                        log_msg(
                            "ERROR",
                            "P2P_NET",
                            Some(node_id_for_thread.clone()),
                            &format!("接受连接失败: {}", e),
                        );
                        thread::sleep(Duration::from_millis(200));
                    }
                }
            }
            log_msg(
                "DEBUG",
                "NODE",
                Some(node_id_for_thread.clone()),
                "监听线程退出。",
            );
        });

        // 发现网络中的其他对等节点
        self.discover_peers();
        log_msg(
            "DEBUG",
            "NODE",
            Some(self.node_id.clone()),
            &format!("进入主循环..."),
        );

        // 初始化定时器
        let mut next_report = Instant::now() + Duration::from_secs(3); // 下次报告状态的时间
        let mut next_consensus =
            Instant::now() + Duration::from_millis(rand::thread_rng().gen_range(1000..2000)); // 下次尝试共识的时间

        // 节点主循环
        while !self.stop_flag.load(Ordering::SeqCst) {
            // 1. 处理新的TCP连接
            match conn_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(stream) => {
                    if let Err(e) = self.handle_connection(stream) {
                        log_msg(
                            "ERROR",
                            "NODE",
                            Some(self.node_id.clone()),
                            &format!("处理连接失败: {}", e),
                        );
                    }
                }
                Err(RecvTimeoutError::Timeout) => {} // 超时，继续执行
                Err(RecvTimeoutError::Disconnected) => break, // 通道断开，退出循环
            }

            // 2. 处理内存池中的消息
            if !self.mempool.is_empty() {
                // log_msg("DEBUG", "SN", Some(self.node_id.clone()), "process_mempool");
                self.process_mempool();
            }

            // 3. 尝试共识
            if Instant::now() >= next_consensus {
                self.attempt_consensus();
                // 为下一次共识尝试设置一个随机的延迟，避免所有节点同时尝试
                next_consensus = Instant::now()
                    + Duration::from_millis(rand::thread_rng().gen_range(1000..2000));
            }

            // 4. 报告节点状态
            if Instant::now() >= next_report {
                self.report_status();
                next_report = Instant::now() + Duration::from_secs(3);
            }
        }

        // 清理和关闭
        self.stop_flag.store(true, Ordering::SeqCst);
        drop(conn_rx); // 关闭通道，让监听线程退出
        if listener_handle.join().is_err() {
            log_msg(
                "WARN",
                "NODE",
                Some(self.node_id.clone()),
                "监听线程 join 失败。",
            );
        }
        log_msg("DEBUG", "NODE", Some(self.node_id.clone()), "节点停止。");
    }

    /// 报告节点的当前状态
    fn report_status(&self) {
        let height = self.chain.height();
        // 获取下一高度的证明池大小
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
        // 通过通道发送报告
        let _ = self.report_sender.send(report);
    }

    /// 处理单个TCP连接
    fn handle_connection(&mut self, stream: TcpStream) -> std::io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        reader.read_line(&mut line)?; // 读取一行JSON数据
        if line.trim().is_empty() {
            return Ok(());
        }
        // 解析命令请求
        let req: CommandRequest = serde_json::from_str(&line).unwrap_or(CommandRequest {
            cmd: String::new(),
            data: Value::Null,
        });
        // 分发命令并获取响应
        let response = self.dispatch_command(req);
        let mut writer = stream;
        let resp_json = serde_json::to_string(&response).unwrap();
        // 写回响应
        writer.write_all(resp_json.as_bytes())?;
        writer.write_all(
            b"
",
        )?;
        Ok(())
    }

    /// 根据命令名称分发到不同的处理函数
    fn dispatch_command(&mut self, req: CommandRequest) -> CommandResponse {
        match req.cmd.as_str() {
            "get_peers" => {
                // 返回当前节点知道的所有对等节点
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
                // 处理一个新节点的宣告，将其加入对等节点列表
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
                // 处理收到的gossip消息
                self.handle_gossip(&req.data);
                CommandResponse {
                    ok: true,
                    error: None,
                    extra: HashMap::new(),
                }
            }
            "inject_gossip" => {
                // 从外部注入一个gossip消息（通常用于模拟和测试）
                self.gossip(req.data, true);
                CommandResponse {
                    ok: true,
                    error: None,
                    extra: HashMap::new(),
                }
            }
            "chunk_distribute" => self.handle_chunk_distribute(&req.data), // 处理文件块分发
            "finalize_storage" => {
                // 完成文件存储的提交阶段
                self.storage_manager.finalize_commitments();
                CommandResponse {
                    ok: true,
                    error: None,
                    extra: HashMap::new(),
                }
            }
            "dpdp_challenge" => self.handle_dpdp_challenge(&req.data), // 处理dPDP挑战请求
            _ => CommandResponse {
                ok: false,
                error: Some(String::from("未知命令")),
                extra: HashMap::new(),
            },
        }
    }

    /// 处理文件块分发请求
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
        // 存储管理器接收并存储文件块
        let ok = self.storage_manager.receive_chunk(&chunk);
        // 如果提供了文件所有者的公钥，则保存
        if let Some(pk_hex) = data.get("owner_pk_beta").and_then(Value::as_str) {
            let pk_bytes = hex::decode(pk_hex).unwrap_or_default();
            if !pk_bytes.is_empty() {
                self.storage_manager
                    .set_file_pk_beta(&chunk.file_id, pk_bytes);
            }
        }
        if ok {
            if let (Some(period), Some(ch_size)) = (
                data.get("storage_period").and_then(Value::as_u64),
                data.get("challenge_size").and_then(Value::as_u64),
            ) {
                self.storage_manager.ensure_cycle_metadata(
                    &chunk.file_id,
                    period as usize,
                    ch_size as usize,
                );
            }
        }
        CommandResponse {
            ok,
            error: None,
            extra: HashMap::new(),
        }
    }

    /// 处理dPDP挑战请求，生成并返回证明
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
        // 获取生成证明所需的上下文信息
        let prev_hash = self.chain.last_hash();
        let timestamp = self
            .chain
            .blocks
            .last()
            .map(|b| (b.timestamp / 1_000_000_000) as u64)
            .unwrap_or_else(|| chrono::Utc::now().timestamp() as u64);

        let (chunks, tags) = self.storage_manager.get_file_data_for_proof(file_id);
        // 调用Prover生成证明
        let challenge_len = self
            .storage_manager
            .challenge_size_for(file_id)
            .unwrap_or_else(|| indices.len().max(1));
        let (proof, challenge, _contributions) = self.prover.prove(
            file_id,
            &chunks,
            &tags,
            &prev_hash,
            timestamp,
            Some(challenge_len),
        );
        log_msg(
            "INFO",
            "dPDP_PROVE",
            Some(self.node_id.clone()),
            &format!("为文件 {} 生成了dPDP证明。", file_id),
        );

        // 构造响应
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

    /// 发现对等节点
    fn discover_peers(&mut self) {
        if let Some(bootstrap) = self.bootstrap_addr {
            // 如果有引导节点地址，则联系引导节点
            log_msg(
                "DEBUG",
                "P2P_DISCOVERY",
                Some(self.node_id.clone()),
                &format!("联系引导节点 {}...", bootstrap),
            );
            // 1. 向引导节点宣告自己的存在
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
            // 2. 从引导节点获取已知的对等节点列表
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
                            // 解析地址并添加到自己的对等节点列表中
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
            // 如果没有引导节点地址，则自己作为引导节点运行
            log_msg(
                "DEBUG",
                "P2P_DISCOVERY",
                Some(self.node_id.clone()),
                "作为引导节点运行。",
            );
        }
    }

    /// 处理Gossip消息
    fn handle_gossip(&mut self, data: &Value) {
        // 1. 检查是否已经处理过此消息
        if let Some(gossip_id) = data.get("gossip_id").and_then(Value::as_str) {
            if self.seen_gossip_ids.contains(gossip_id) {
                return; // 如果见过，则直接返回，避免循环和重复处理
            }
            self.seen_gossip_ids.insert(gossip_id.to_string());
        }

        // 2. 根据消息类型进行处理
        if let Some(msg_type) = data.get("type").and_then(Value::as_str) {
            match msg_type {
                "storage_offer" => {
                    // 处理存储报价：如果自己有能力存储，则向发起者发送投标
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
                                        let _ = send_json_line_without_response(addr, &payload);
                                    }
                                }
                            }
                        }
                    }
                }
                "bobtail_proof" | "preprepare_sync" | "new_block" => {
                    // 将共识相关的消息放入内存池等待处理
                    self.mempool.push_back(data.clone());
                }
                "tst_update" => {
                    // 处理时间状态树（TST）更新消息
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

        // 3. 将消息继续gossip给其他对等节点
        self.gossip(data.clone(), false);
    }

    /// 将消息gossip给所有已知的对等节点
    fn gossip(&mut self, mut message: Value, originator: bool) {
        if originator {
            // 如果是消息的源头，则创建一个唯一的gossip ID
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
        // 向所有对等节点发送gossip命令
        for addr in self.peers.values() {
            let _ = send_json_line_without_response(
                *addr,
                &serde_json::json!({"cmd": "gossip", "data": message.clone()}),
            );
        }
    }

    /// 处理内存池中的消息
    fn process_mempool(&mut self) {
        let next_height = self.chain.height() + 1;

        // 优先处理新区块消息
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
                        // 验证并添加新区块
                        if block.prev_hash == self.chain.last_hash() {
                            self.chain.add_block(block.clone(), None);
                            log_msg(
                                "INFO",
                                "BLOCKCHAIN",
                                Some(self.node_id.clone()),
                                &format!("接受了来自 {} 的区块 {}", block.leader_id, block.height),
                            );
                            // 区块接受后，执行dPDP轮次
                            self.perform_dpdp_round(&block);
                            // 清理当前高度的共识状态
                            self.proof_pool.remove(&next_height);
                            self.preprepare_signals.remove(&next_height);
                            self.sent_preprepare_signal_at.remove(&next_height);
                            self.election_concluded_for.insert(next_height);
                        }
                    }
                }
            }
            return; // 优先处理完区块后直接返回
        }

        // 处理其他共识消息
        if let Some(msg) = self.mempool.pop_front() {
            let height = msg
                .get("height")
                .and_then(Value::as_u64)
                .map(|h| h as usize)
                .unwrap_or(0);
            // 忽略过时或已完成选举高度的消息
            if height < self.chain.height() + 1 || self.election_concluded_for.contains(&height) {
                return;
            }
            match msg.get("type").and_then(Value::as_str) {
                Some("bobtail_proof") => {
                    // 将收到的Bobtail证明存入证明池
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
                    // 同步其他节点的预备信号
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

    /// 尝试进行共识
    fn attempt_consensus(&mut self) {
        // 如果没有存储文件，则不参与共识
        if self.storage_manager.get_num_files() == 0 {
            return;
        }
        let height = self.chain.height() + 1;
        if self.election_concluded_for.contains(&height) {
            return;
        }

        // 1. 如果自己还没有为当前高度生成证明，则尝试挖矿
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
                10_000, // 挖矿迭代次数
            );
            if let Some(proof) = proofs.first() {
                // 将挖出的证明存入自己的证明池
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
                // 将新挖出的证明gossip出去
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

        // 2. 尝试选举领导者
        self.try_elect_leader(height);
    }

    /// 尝试选举领导者
    fn try_elect_leader(&mut self, height: usize) {
        if self.election_concluded_for.contains(&height) {
            return;
        }

        // 阶段1: 预备 (Pre-prepare)
        // 如果尚未发送预备信号
        if !self.sent_preprepare_signal_at.contains_key(&height) {
            let mut proofs: Vec<BobtailProof> = self
                .proof_pool
                .get(&height)
                .map(|m| m.values().cloned().collect())
                .unwrap_or_default();
            // 如果收集到的证明数量足够
            if proofs.len() >= self.bobtail_k + self.prepare_margin {
                proofs.sort_by(|a, b| a.proof_hash.cmp(&b.proof_hash)); // 按哈希排序
                let selected = proofs[..self.bobtail_k].to_vec(); // 选择前k个最好的证明
                                                                  // 计算平均哈希
                let avg_hash = selected
                    .iter()
                    .map(|p| BigUint::parse_bytes(p.proof_hash.as_bytes(), 16).unwrap_or_default())
                    .fold(BigUint::from(0u32), |acc, x| acc + x)
                    / BigUint::from(self.bobtail_k as u32);

                // 如果平均哈希满足难度要求
                if avg_hash <= self.difficulty_threshold {
                    let proof_hashes: Vec<String> =
                        selected.iter().map(|p| p.proof_hash.clone()).collect();
                    // 记录自己发送的预备信号
                    self.sent_preprepare_signal_at
                        .insert(height, proof_hashes.clone());
                    // 将自己的信号加入信号池
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

        // 阶段2: 准备/提交 (Prepare/Commit)
        // 如果已经发送了预备信号，则开始同步和计票
        if let Some(signals_snapshot) = self.preprepare_signals.get(&height).cloned() {
            // 将自己的信号gossip出去，以便其他节点同步
            self.gossip(
                serde_json::json!({
                    "type": "preprepare_sync",
                    "height": height,
                    "sender_id": self.node_id,
                    "signals": signals_snapshot,
                }),
                true,
            );

            // 对收到的所有提案（信号）进行计票
            let mut votes: HashMap<Vec<String>, Vec<String>> = HashMap::new();
            for (sender, proof_hashes) in &signals_snapshot {
                votes
                    .entry(proof_hashes.clone())
                    .or_default()
                    .push(sender.clone());
            }

            // 检查是否有提案获得了足够的票数（k票）
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

                    // 检查自己是否拥有所有获胜的证明，如果没有则等待同步
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

                    // 选举领导者：获胜证明集合中哈希最小的证明的创建者
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

                    // 如果自己是领导者，则创建区块
                    if leader_id == self.node_id {
                        self.create_block(height, winning);
                    }

                    // 标记当前高度的选举已结束
                    self.election_concluded_for.insert(height);
                    return; // 选举结束，退出函数
                }
            }
        }
    }

    /// 创建新区块（仅由领导者调用）
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

        // 收集并验证上一轮的dPDP证明
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

        // 验证所有获胜者提交的dPDP证明
        for nid in &winners_ids {
            if let Some(update) = updates_for_prev.get(nid) {
                for (fid, pkg_val) in &update.dpdp_proofs {
                    let Some(pkg_obj) = pkg_val.as_object() else {
                        log_msg(
                            "ERROR",
                            "CONSENSUS",
                            Some(self.node_id.clone()),
                            &format!(
                                "节点 {} 文件 {} 提供的 dPDP 数据格式错误，放弃本次出块。",
                                nid, fid
                            ),
                        );
                        return;
                    };

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
                        sk_alpha: BigUint::from(0u32), // 验证时不需要私钥
                    };

                    let pending_rounds = pkg_obj
                        .get("pending_rounds")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    if pending_rounds.is_empty() {
                        if pkg_obj.get("final_fold").is_none() {
                            log_msg(
                                "WARN",
                                "CONSENSUS",
                                Some(self.node_id.clone()),
                                &format!("节点 {} 文件 {} 未提供任何待验证的折叠轮次。", nid, fid),
                            );
                        }
                    }

                    for round_val in pending_rounds {
                        let Some(round_obj) = round_val.as_object() else {
                            log_msg(
                                "WARN",
                                "CONSENSUS",
                                Some(self.node_id.clone()),
                                &format!(
                                    "节点 {} 文件 {} 存在格式异常的折叠轮次，忽略。",
                                    nid, fid
                                ),
                            );
                            continue;
                        };

                        let round_idx = round_obj
                            .get("round")
                            .and_then(Value::as_u64)
                            .unwrap_or_default();
                        let challenge_entries = round_obj
                            .get("challenge")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        let challenge: Vec<(usize, BigUint)> = challenge_entries
                            .iter()
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
                            .collect();

                        let proof_val = round_obj.get("proof").cloned().unwrap_or(Value::Null);
                        let proof = match serde_json::from_value::<DPDPProof>(proof_val) {
                            Ok(p) => p,
                            Err(e) => {
                                log_msg(
                                    "ERROR",
                                    "CONSENSUS",
                                    Some(self.node_id.clone()),
                                    &format!(
                                        "dPDP 证明解析失败：节点 {} 文件 {} 轮次 {} 错误 {}",
                                        nid, fid, round_idx, e
                                    ),
                                );
                                return;
                            }
                        };

                        if !DPDP::check_proof(&params, &proof, &challenge) {
                            log_msg(
                                "CRITICAL",
                                "CONSENSUS",
                                Some(self.node_id.clone()),
                                &format!(
                                    "dPDP 证明验证失败：节点 {} 文件 {} 轮次 {}，放弃本次出块。",
                                    nid, fid, round_idx
                                ),
                            );
                            return;
                        }
                    }
                }
            }
        }

        // 构造区块体
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
                .map(|p| (p.address.clone(), String::from("1"))) // 奖励分配
                .collect(),
            proofs_merkle_tree: proofs_merkle_tree,
            dpdp_challenges,
        };

        // 构造完整区块
        let new_block = Block {
            height: height as u64,
            prev_hash: self.chain.last_hash(),
            seed: self.chain.last_hash(),
            leader_id: self.node_id.clone(),
            accum_proof_hash: String::from("placeholder"), // 占位符
            merkle_roots: HashMap::from([(String::from("proofs_merkle_root"), proofs_merkle_root)]),
            round_proof_stmt_hash: String::from("placeholder"), // 占位符
            body,
            time_tree_roots: winners_roots,
            bobtail_k: self.bobtail_k as u64,
            bobtail_target: format!("{:x}", self.difficulty_threshold),
            timestamp: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128,
        };

        // 将新区块gossip出去
        self.gossip(
            serde_json::json!({
                "type": "new_block",
                "height": height,
                "block": new_block,
            }),
            true,
        );
    }

    /// 在接受一个新区块后，执行dPDP轮次
    fn perform_dpdp_round(&mut self, accepted_block: &Block) {
        if self.storage_manager.get_num_files() == 0 {
            return;
        }
        let mut challenges_by_file: HashMap<String, Vec<ChallengeEntry>> = HashMap::new();
        let mut latest_results: HashMap<String, Value> = HashMap::new();
        let file_ids = self.storage_manager.list_file_ids();

        // 为自己存储的每个文件生成dPDP证明
        for fid in &file_ids {
            let (chunks, tags) = self.storage_manager.get_file_data_for_proof(fid);
            let challenge_len = self
                .storage_manager
                .challenge_size_for(fid)
                .unwrap_or_else(|| tags.len().max(1));
            let (proof, challenge, contributions) = self.prover.prove(
                fid,
                &chunks,
                &tags,
                &accepted_block.prev_hash,
                (accepted_block.timestamp / 1_000_000_000) as u64,
                Some(challenge_len),
            );
            let entries: Vec<ChallengeEntry> = challenge
                .iter()
                .map(|(i, v)| ChallengeEntry(*i, v.to_string()))
                .collect();
            challenges_by_file.insert(fid.clone(), entries);

            let round_salt = format!("{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
            if let Some(result) = self.storage_manager.process_round(
                fid,
                accepted_block,
                &proof,
                &challenge,
                &contributions,
                &round_salt,
            ) {
                latest_results.insert(
                    fid.clone(),
                    serde_json::json!({
                        "accumulator": result.accumulator.to_string(),
                        "step": result.step_index,
                    }),
                );
            }
        }

        let mut pending_rounds = self.storage_manager.drain_pending_rounds();
        let mut final_folds = self.storage_manager.take_final_folds();
        let mut dpdp_proofs_by_file: HashMap<String, Value> = HashMap::new();
        for fid in &file_ids {
            let pk_hex = self
                .storage_manager
                .get_file_pk_beta(fid)
                .map(|bytes| hex::encode(bytes))
                .unwrap_or_default();
            let pending = pending_rounds.remove(fid).unwrap_or_default();
            let final_fold = final_folds.remove(fid);
            let latest = latest_results.get(fid).cloned();
            dpdp_proofs_by_file.insert(
                fid.clone(),
                serde_json::json!({
                    "pk_beta": pk_hex,
                    "pending_rounds": pending,
                    "latest": latest,
                    "final_fold": final_fold,
                }),
            );
        }

        // 将自己的dPDP结果（作为下一轮的状态更新）gossip出去
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

        // 同时更新自己的本地状态
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

/// 解析 "announce" 命令的数据
fn parse_announce(data: &Value) -> Option<(String, SocketAddr)> {
    let node_id = data.get("node_id")?.as_str()?.to_string();
    let host = data.get("host")?.as_str()?;
    let port = data.get("port")?.as_u64()? as u16;
    Some((node_id, SocketAddr::new(host.parse().ok()?, port)))
}

/// 异步发送JSON行数据，不等待响应
pub fn send_json_line_without_response(addr: SocketAddr, payload: &Value) -> bool {
    let payload_clone = payload.clone();
    thread::spawn(move || {
        let _ = send_json_line(addr, &payload_clone);
    });
    true
}

/// 同步发送JSON行数据，并等待响应
pub fn send_json_line(addr: SocketAddr, payload: &Value) -> Option<Value> {
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(1500)) {
        let json = serde_json::to_string(payload).ok()?;
        let _ = stream.write_all(json.as_bytes());
        let _ = stream.write_all(
            b"
",
        );
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
