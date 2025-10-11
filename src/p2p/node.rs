use std::collections::{hash_map::Entry, BTreeMap, HashMap, HashSet, VecDeque}; // 集合类型
use std::io::{self, BufRead, BufReader, Write}; // IO 操作
use std::net::{SocketAddr, TcpListener, TcpStream as StdTcpStream}; // 网络地址和TCP流
use std::sync::atomic::{AtomicBool, Ordering}; // 原子布尔值，用于线程安全地停止节点
use std::sync::Arc; // 原子引用计数，用于多线程共享数据
use std::thread; // 线程操作
use std::time::{Duration, Instant}; // 时间相关操作

use crossbeam_channel::{unbounded, Receiver, Sender}; // 高性能的并发消息通道
use futures::future::join_all;
use num_bigint::BigUint; // 大整数处理
use num_traits::{ops::checked::CheckedSub, Zero};
use rand::seq::SliceRandom;
use rand::Rng; // 随机数生成
use serde::{Deserialize, Serialize}; // 序列化和反序列化
use serde_json::{Map, Value}; // JSON处理
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime};
use tokio::time::{sleep as tokio_sleep, timeout};

use ark_bn254::{G1Affine, G2Affine}; // BN254椭圆曲线上的点
use ark_ec::AffineRepr; // 椭圆曲线点的仿射表示

use once_cell::sync::Lazy;

// 导入项目内部模块
use crate::common::datastructures::{
    Block, BlockBody, BobtailProof, ChallengeEntry, DPDPParams, DPDPProof, FileChunk, ProofSummary,
}; // 数据结构
use crate::consensus::blockchain::Blockchain; // 区块链逻辑
use crate::crypto::deserialize_g2; // G2点反序列化工具
use crate::crypto::dpdp::DPDP; // dPDP 密码学逻辑
use crate::roles::miner::Miner; // 矿工角色
use crate::roles::prover::Prover; // 证明者角色
use crate::storage::manager::{FileDataError, StorageManager}; // 存储管理器
use crate::utils::{build_merkle_tree, h_join, log_msg, with_cpu_heavy_limit}; // 工具函数

pub const DEFAULT_DIFFICULTY_HEX: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

static TOKIO_RUNTIME: Lazy<TokioRuntime> = Lazy::new(|| {
    TokioRuntimeBuilder::new_multi_thread()
        .thread_name("bpst-async")
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime")
});

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

/// 处理新区块时的结果
enum BlockHandlingResult {
    Accepted,
    Deferred(Box<Block>),
    Ignored,
}

enum BranchBuildError {
    MissingAncestor,
    Invalid,
}

/// P2P网络中的核心节点结构体
pub struct Node {
    pub node_id: String,                                         // 节点的唯一标识符
    listen_host: String,                                         // 节点监听的主机地址
    advertise_host: String,                                      // 对外通告的主机地址
    port: u16,                                                   // 节点监听的端口
    bootstrap_addr: Option<SocketAddr>, // 引导节点的地址，如果没有则自己是引导节点
    storage_manager: StorageManager,    // 存储管理器，负责文件的存储和检索
    prover: Prover,                     // 证明者，负责生成dPDP证明
    miner: Miner,                       // 矿工，负责挖矿（生成Bobtail证明）
    peers: HashMap<String, SocketAddr>, // 对等节点列表 <node_id, addr>
    mempool: VecDeque<Value>,           // 内存池，暂存待处理的gossip消息
    new_block_buffer: VecDeque<Block>,  // 新区块消息缓冲区
    outstanding_proof_requests: HashMap<usize, HashSet<String>>, // 尚未满足的证明请求
    proof_pool: HashMap<usize, HashMap<String, BobtailProof>>, // 证明池 <height, <node_id, proof>>
    known_blocks: HashMap<String, Block>, // 已知区块索引
    seen_gossip_ids: HashSet<String>,   // 已见过的gossip消息ID，防止重复处理
    seen_gossip_order: VecDeque<String>, // gossip消息ID的插入顺序，用于限制缓存大小
    chain: Blockchain,                  // 节点的区块链实例
    bobtail_k: usize,                   // Bobtail共识算法中的k参数
    difficulty_threshold: BigUint,      // 挖矿难度阈值
    broadcast_threshold: BigUint,       // 广播阈值，略高于全局难度
    election_concluded_for: HashSet<usize>, // 记录已完成领导者选举的高度
    round_tst_updates: HashMap<usize, HashMap<String, RoundUpdate>>, // 轮次状态更新 <height, <node_id, update>>
    stop_flag: Arc<AtomicBool>,                                      // 优雅停机的标志
    report_sender: Sender<NodeReport>,                               // 用于发送节点状态报告的通道
    mined_proof_tx: Sender<(usize, BobtailProof)>,                   // 向主线程报告挖矿结果
    mined_proof_rx: Receiver<(usize, BobtailProof)>,                 // 接收挖矿线程的证明
    mining_thread: Option<thread::JoinHandle<()>>,                   // 当前的挖矿线程
    mining_stop_flag: Option<Arc<AtomicBool>>,                       // 挖矿线程的停止标志
    current_mining_height: Option<usize>,                            // 当前挖矿目标高度
    mining_window_size: u64,                                         // 单次挖矿窗口大小
}

impl Node {
    const MAX_SEEN_GOSSIP_IDS: usize = 50_000;
    const GOSSIP_DEFAULT_TTL: u32 = 6;
    const GOSSIP_FANOUT: usize = 4;
    const MIN_ACTIVE_PEERS: usize = 3;
    const MAX_ACTIVE_PEERS: usize = 24;
    const BLOCK_DOWNLOAD_BATCH_SIZE: usize = 8;
    const MAX_BLOCK_RANGE: usize = 64;

    fn has_seen_gossip(&self, gossip_id: &str) -> bool {
        self.seen_gossip_ids.contains(gossip_id)
    }

    fn record_seen_gossip_id(&mut self, gossip_id: String) {
        if self.seen_gossip_ids.insert(gossip_id.clone()) {
            self.seen_gossip_order.push_back(gossip_id);
            if self.seen_gossip_order.len() > Self::MAX_SEEN_GOSSIP_IDS {
                if let Some(oldest) = self.seen_gossip_order.pop_front() {
                    self.seen_gossip_ids.remove(&oldest);
                }
            }
        }
    }

    /// 创建一个新的Node实例
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: String,
        listen_host: String,
        advertise_host: String,
        port: u16,
        bootstrap_addr: Option<SocketAddr>,
        initial_peers: Vec<(String, SocketAddr)>,
        chunk_size: usize,
        max_storage: usize,
        bobtail_k: usize,
        difficulty_override: Option<BigUint>,
        report_sender: Sender<NodeReport>,
    ) -> Self {
        // 初始化挖矿难度阈值
        let difficulty_threshold = difficulty_override.unwrap_or_else(|| {
            BigUint::parse_bytes(DEFAULT_DIFFICULTY_HEX.as_bytes(), 16).unwrap()
        });
        let broadcast_threshold = Self::calculate_broadcast_threshold(&difficulty_threshold);
        let (mined_proof_tx, mined_proof_rx) = unbounded::<(usize, BobtailProof)>();
        Self {
            storage_manager: StorageManager::new(node_id.clone(), chunk_size, max_storage),
            prover: Prover::new(node_id.clone()),
            miner: Miner::new(node_id.clone(), format!("addr:{}", node_id)),
            node_id,
            listen_host,
            advertise_host,
            port,
            bootstrap_addr,
            peers: initial_peers.into_iter().collect(),
            mempool: VecDeque::new(),
            proof_pool: HashMap::new(),
            known_blocks: HashMap::new(),
            seen_gossip_ids: HashSet::new(),
            seen_gossip_order: VecDeque::new(),
            chain: Blockchain::new(),
            bobtail_k,
            difficulty_threshold,
            broadcast_threshold,
            election_concluded_for: HashSet::new(),
            round_tst_updates: HashMap::new(),
            stop_flag: Arc::new(AtomicBool::new(false)),
            report_sender,
            mined_proof_tx,
            mined_proof_rx,
            mining_thread: None,
            mining_stop_flag: None,
            current_mining_height: None,
            mining_window_size: 10_000,
            new_block_buffer: VecDeque::new(),
            outstanding_proof_requests: HashMap::new(),
        }
    }

    fn calculate_broadcast_threshold(difficulty_threshold: &BigUint) -> BigUint {
        let mut candidate =
            (difficulty_threshold.clone() * BigUint::from(11u32)) / BigUint::from(10u32);
        if candidate <= *difficulty_threshold {
            candidate = difficulty_threshold.clone() + BigUint::from(1u32);
        }
        candidate
    }

    /// 获取节点的停止句柄，用于从外部停止节点
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    /// 运行节点的主循环
    pub fn run(mut self) {
        let addr = SocketAddr::new(self.listen_host.parse().unwrap(), self.port);
        // 绑定TCP监听器
        let listener = match TcpListener::bind(addr) {
            Ok(l) => {
                log_msg(
                    "INFO",
                    "P2P_NET",
                    Some(self.node_id.clone()),
                    &format!("在 {}:{} 上监听", self.listen_host, self.port),
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
        let (conn_tx, conn_rx) = unbounded::<StdTcpStream>();
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
        self.sync_main_chain();
        // log_msg(
        //     "DEBUG",
        //     "NODE",
        //     Some(self.node_id.clone()),
        //     &"进入主循环...".to_string(),
        // );

        // 初始化定时器
        let mut next_report = Instant::now() + Duration::from_secs(3); // 下次报告状态的时间
        let mut next_consensus =
            Instant::now() + Duration::from_millis(rand::thread_rng().gen_range(1000..2000)); // 下次尝试共识的时间
        let mut next_peer_refresh = Instant::now() + Duration::from_secs(30);
        let mut next_chain_sync = Instant::now() + Duration::from_secs(20);

        // 节点主循环
        while !self.stop_flag.load(Ordering::SeqCst) {
            // 1. 处理新的TCP连接
            // 1. 处理新的TCP连接
            match conn_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(stream) => {
                    if let Err(e) = self.handle_connection(stream) {
                        // 只有当错误不是常见的瞬时网络错误时，才将其记录为严重错误
                        if !matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                        ) {
                            log_msg(
                                "ERROR",
                                "NODE",
                                Some(self.node_id.clone()),
                                &format!("处理连接失败: {}", e),
                            );
                        }
                        // (否则，如果是 WouldBlock/Timeout，我们就静默地忽略它，因为这只是一个客户端超时)
                    }
                }
                Err(_) => {
                    // 如果接收超时，继续执行循环的下一次迭代
                }
            }

            // 2. 处理新区块缓冲区和内存池中的消息
            self.process_new_block_buffer();
            if !self.mempool.is_empty() {
                // log_msg("DEBUG", "SN", Some(self.node_id.clone()), "process_mempool");
                self.process_mempool();
            }

            self.drain_mined_proofs();

            if Instant::now() >= next_peer_refresh {
                self.drop_unreachable_peers();
                next_peer_refresh = Instant::now() + Duration::from_secs(30);
            }

            if Instant::now() >= next_chain_sync {
                self.sync_main_chain();
                next_chain_sync = Instant::now() + Duration::from_secs(20);
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
        self.stop_mining_thread();
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
    fn handle_connection(&mut self, stream: StdTcpStream) -> std::io::Result<()> {
        // Windows sockets inherit the listener's non-blocking flag. Force the
        // per-connection stream back into blocking mode before layering
        // timeouts so that synchronous reads/writes behave consistently with
        // other platforms.
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
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
        let resp_json = serde_json::to_string(&response)?;
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
                    serde_json::json!([self.advertise_host.clone(), self.port]),
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
                let mut message = req.data;
                if let Value::Object(ref mut map) = message {
                    map.entry(String::from("gossip_id")).or_insert_with(|| {
                        Value::from(format!(
                            "{}:{}",
                            self.node_id,
                            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                        ))
                    });
                    map.entry(String::from("ttl"))
                        .or_insert_with(|| Value::from(Self::GOSSIP_DEFAULT_TTL as u64));
                }
                self.handle_gossip(&message);
                CommandResponse {
                    ok: true,
                    error: None,
                    extra: HashMap::new(),
                }
            }
            "chain_status" => {
                let mut extra = HashMap::new();
                extra.insert(
                    String::from("height"),
                    Value::from(self.chain.height() as u64),
                );
                extra.insert(String::from("head"), Value::from(self.chain.last_hash()));
                CommandResponse {
                    ok: true,
                    error: None,
                    extra,
                }
            }
            "get_block_range" => self.handle_get_block_range(&req.data),
            "ping" => CommandResponse {
                ok: true,
                error: None,
                extra: HashMap::new(),
            },
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
            "query_final_proof" => self.handle_query_final_proof(&req.data),
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
        let total_chunks = data
            .get("total_chunks")
            .and_then(Value::as_u64)
            .map(|v| v as usize);
        // 存储管理器接收并存储文件块
        let ok = self.storage_manager.receive_chunk(&chunk, total_chunks);
        // 如果提供了文件所有者的公钥，则保存
        if let Some(pk_hex) = data.get("owner_pk_beta").and_then(Value::as_str) {
            let pk_bytes = hex::decode(pk_hex).unwrap_or_default();
            if !pk_bytes.is_empty() {
                self.storage_manager
                    .set_file_pk_beta(&chunk.file_id, pk_bytes);
            }
        }
        if let Some(owner_addr) = data
            .get("owner_addr")
            .and_then(Value::as_array)
            .and_then(|arr| {
                let host = arr.first()?.as_str()?;
                let port = arr.get(1)?.as_u64()? as u16;
                Some(SocketAddr::new(host.parse().ok()?, port))
            })
        {
            self.storage_manager
                .set_file_owner_contact(&chunk.file_id, owner_addr);
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
        if !self.storage_manager.has_file(file_id) {
            return CommandResponse {
                ok: false,
                error: Some(String::from("文件未存储或已完成任务")),
                extra: HashMap::new(),
            };
        }
        if self.storage_manager.is_file_expired(file_id) {
            return CommandResponse {
                ok: false,
                error: Some(String::from("文件存储周期已结束，停止生成证明")),
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

        let (chunks, tags) = match self.storage_manager.get_file_data_for_proof(file_id) {
            Ok(data) => data,
            Err(FileDataError::Incomplete { missing_indices }) => {
                self.request_missing_chunks(file_id, &missing_indices);
                let mut extra = HashMap::new();
                extra.insert(
                    String::from("missing_indices"),
                    Value::from(
                        missing_indices
                            .iter()
                            .map(|idx| Value::from(*idx as u64))
                            .collect::<Vec<_>>(),
                    ),
                );
                return CommandResponse {
                    ok: false,
                    error: Some(String::from("文件数据不完整，已请求补发缺失块")),
                    extra,
                };
            }
            Err(FileDataError::Expired) => {
                return CommandResponse {
                    ok: false,
                    error: Some(String::from("文件存储周期已结束，停止生成证明")),
                    extra: HashMap::new(),
                };
            }
            Err(FileDataError::NotFound) => {
                return CommandResponse {
                    ok: false,
                    error: Some(String::from("文件数据不可用")),
                    extra: HashMap::new(),
                };
            }
        };
        // 调用Prover生成证明
        let challenge_len = self
            .storage_manager
            .challenge_size_for(file_id)
            .unwrap_or_else(|| indices.len().max(1));
        let (proof, challenge) = with_cpu_heavy_limit(|| {
            let (proof, challenge, _contributions) = self.prover.prove(
                file_id,
                &chunks,
                &tags,
                &prev_hash,
                timestamp,
                Some(challenge_len),
            );
            (proof, challenge)
        });
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

    fn request_missing_chunks(&self, file_id: &str, missing_indices: &[usize]) {
        if missing_indices.is_empty() {
            return;
        }
        let Some(owner_addr) = self.storage_manager.get_file_owner_contact(file_id) else {
            log_msg(
                "WARN",
                "STORE",
                Some(self.node_id.clone()),
                &format!("无法请求补发文件 {} 的缺失块：未记录所有者地址。", file_id),
            );
            return;
        };
        let payload = serde_json::json!({
            "cmd": "request_missing_chunks",
            "data": {
                "file_id": file_id,
                "missing_indices": missing_indices.iter().map(|i| *i as u64).collect::<Vec<_>>(),
                "provider_id": self.node_id,
                "provider_addr": [self.advertise_host.clone(), self.port],
            }
        });
        if send_json_line(owner_addr, &payload).is_some() {
            log_msg(
                "INFO",
                "STORE",
                Some(self.node_id.clone()),
                &format!(
                    "已向文件 {} 的所有者请求补发缺失块：{:?}",
                    file_id, missing_indices
                ),
            );
        } else {
            log_msg(
                "WARN",
                "STORE",
                Some(self.node_id.clone()),
                &format!(
                    "请求文件 {} 缺失块失败，无法联系所有者 {}。",
                    file_id, owner_addr
                ),
            );
        }
    }

    fn handle_query_final_proof(&self, data: &Value) -> CommandResponse {
        let file_id = data
            .get("file_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if file_id.is_empty() {
            return CommandResponse {
                ok: false,
                error: Some(String::from("缺少 file_id")),
                extra: HashMap::new(),
            };
        }

        let mut result: Option<(u64, String, Value, Value, bool)> = None;
        'outer: for block in self.chain.blocks.iter().rev() {
            for (provider_id, files) in &block.body.dpdp_proofs {
                if let Some(pkg) = files.get(&file_id) {
                    let final_fold = pkg.get("final_fold").cloned().unwrap_or(Value::Null);
                    let has_final = !final_fold.is_null();
                    result = Some((
                        block.height,
                        provider_id.clone(),
                        pkg.clone(),
                        final_fold,
                        has_final,
                    ));
                    if has_final {
                        break 'outer;
                    }
                }
            }
        }

        match result {
            Some((height, provider_id, package, final_fold, has_final)) => {
                let mut extra = HashMap::new();
                extra.insert(String::from("block_height"), Value::from(height));
                extra.insert(String::from("provider_id"), Value::String(provider_id));
                extra.insert(String::from("package"), package);
                extra.insert(String::from("final_fold"), final_fold);
                extra.insert(String::from("has_final_proof"), Value::Bool(has_final));
                CommandResponse {
                    ok: true,
                    error: None,
                    extra,
                }
            }
            None => CommandResponse {
                ok: false,
                error: Some(String::from("未找到对应的最终证明")),
                extra: HashMap::new(),
            },
        }
    }

    /// 发现对等节点
    fn discover_peers(&mut self) {
        if !self.peers.is_empty() {
            log_msg(
                "INFO",
                "P2P_DISCOVERY",
                Some(self.node_id.clone()),
                &format!("已加载 {} 个初始对等节点记录。", self.peers.len()),
            );
        }

        if let Some(bootstrap) = self.bootstrap_addr {
            let initial = self.peers.is_empty();
            self.fetch_peers_from_bootstrap(bootstrap, initial);
        } else if self.peers.is_empty() {
            // 如果没有引导节点地址，则自己作为引导节点运行
            log_msg(
                "DEBUG",
                "P2P_DISCOVERY",
                Some(self.node_id.clone()),
                "作为引导节点运行。",
            );
        }

        self.prune_peer_set();
        self.drop_unreachable_peers();
    }

    fn fetch_peers_from_bootstrap(&mut self, bootstrap: SocketAddr, initial: bool) {
        let announce_payload = serde_json::json!({
            "cmd": "announce",
            "data": {
                "node_id": self.node_id,
                "host": self.advertise_host.clone(),
                "port": self.port,
            }
        });

        if initial {
            log_msg(
                "DEBUG",
                "P2P_DISCOVERY",
                Some(self.node_id.clone()),
                &format!("联系引导节点 {} 以获取初始对等节点...", bootstrap),
            );
        } else {
            log_msg(
                "DEBUG",
                "P2P_DISCOVERY",
                Some(self.node_id.clone()),
                &format!("向引导节点 {} 请求最新对等节点列表...", bootstrap),
            );
        }

        let _ = send_json_line(bootstrap, &announce_payload);
        let before = self.peers.len();
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
                                    addr_arr.first().and_then(Value::as_str),
                                    addr_arr.get(1).and_then(Value::as_u64),
                                ) {
                                    if let Ok(ip) = host.parse() {
                                        self.peers
                                            .insert(nid.clone(), SocketAddr::new(ip, port as u16));
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
        let after = self.peers.len();
        if after > before {
            log_msg(
                "INFO",
                "P2P_DISCOVERY",
                Some(self.node_id.clone()),
                &format!(
                    "当前已知 {} 个对等节点（新增 {} 个）。",
                    after,
                    after - before
                ),
            );
        }
    }

    fn prune_peer_set(&mut self) {
        if self.peers.len() <= Self::MAX_ACTIVE_PEERS {
            return;
        }
        let bootstrap_addr = self.bootstrap_addr;
        let mut entries: Vec<(String, SocketAddr)> = self
            .peers
            .iter()
            .map(|(id, addr)| (id.clone(), *addr))
            .collect();
        let mut keep: HashSet<String> = HashSet::new();
        if let Some(addr) = bootstrap_addr {
            if let Some((id, _)) = entries.iter().find(|(_, peer_addr)| *peer_addr == addr) {
                keep.insert(id.clone());
            }
        }
        entries.retain(|(id, _)| !keep.contains(id));
        entries.shuffle(&mut rand::thread_rng());
        for (id, _) in entries.into_iter() {
            if keep.len() >= Self::MAX_ACTIVE_PEERS {
                break;
            }
            keep.insert(id);
        }
        self.peers
            .retain(|node_id, addr| keep.contains(node_id) || Some(*addr) == bootstrap_addr);
    }

    fn drop_unreachable_peers(&mut self) {
        if self.peers.is_empty() {
            return;
        }
        let snapshot: Vec<(String, SocketAddr)> = self
            .peers
            .iter()
            .map(|(id, addr)| (id.clone(), *addr))
            .collect();
        let mut removed = Vec::new();
        for (peer_id, addr) in snapshot {
            if peer_id == self.node_id {
                continue;
            }
            let ping = serde_json::json!({
                "cmd": "ping",
                "data": {"from": self.node_id.clone()},
            });
            let reachable = send_json_line(addr, &ping)
                .and_then(|resp| resp.get("ok").and_then(Value::as_bool))
                .unwrap_or(false);
            if !reachable {
                removed.push(peer_id);
            }
        }
        for peer_id in removed {
            self.peers.remove(&peer_id);
        }
        if self.peers.len() < Self::MIN_ACTIVE_PEERS {
            if let Some(bootstrap) = self.bootstrap_addr {
                self.fetch_peers_from_bootstrap(bootstrap, false);
            }
        }
        self.prune_peer_set();
    }

    fn sync_main_chain(&mut self) {
        if self.peers.is_empty() {
            return;
        }
        let local_height = self.chain.height();
        let peer_snapshot: Vec<(String, SocketAddr)> = self
            .peers
            .iter()
            .map(|(id, addr)| (id.clone(), *addr))
            .collect();
        if peer_snapshot.is_empty() {
            return;
        }

        let mut peer_status = Vec::new();
        for (peer_id, addr) in &peer_snapshot {
            let payload = serde_json::json!({"cmd": "chain_status", "data": {}});
            if let Some(resp) = send_json_line(*addr, &payload) {
                if resp.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                    let height = resp
                        .get("height")
                        .and_then(Value::as_u64)
                        .map(|v| v as usize)
                        .unwrap_or(0);
                    let head = resp
                        .get("head")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    peer_status.push((peer_id.clone(), *addr, height, head));
                }
            }
        }

        if peer_status.is_empty() {
            return;
        }

        let Some(target_height) = peer_status.iter().map(|(_, _, height, _)| *height).max() else {
            return;
        };

        if target_height <= local_height {
            return;
        }

        let start_height = local_height + 1;
        let eligible: Vec<SocketAddr> = peer_status
            .iter()
            .filter(|(_, _, height, _)| *height >= start_height)
            .map(|(_, addr, _, _)| *addr)
            .collect();
        if eligible.is_empty() {
            return;
        }

        let mut ranges = Vec::new();
        let mut current = start_height;
        while current <= target_height {
            let end = std::cmp::min(current + Self::BLOCK_DOWNLOAD_BATCH_SIZE - 1, target_height);
            ranges.push((current, end));
            current = end + 1;
        }

        let mut requests = Vec::new();
        let mut addr_iter = eligible.iter().cycle();
        for (start, end) in ranges {
            if let Some(addr) = addr_iter.next() {
                requests.push((*addr, start, end));
            } else {
                break;
            }
        }

        let downloaded = Self::download_block_ranges_parallel(requests);
        if downloaded.is_empty() {
            return;
        }

        let mut ordered: BTreeMap<usize, Block> = BTreeMap::new();
        for block in downloaded {
            let height = block.height as usize;
            if height >= start_height && height <= target_height {
                ordered.entry(height).or_insert(block);
            }
        }

        let mut deferred = Vec::new();
        for (_height, block) in ordered.into_iter() {
            match self.try_process_block(block) {
                BlockHandlingResult::Accepted => {}
                BlockHandlingResult::Deferred(block) => deferred.push(*block),
                BlockHandlingResult::Ignored => {}
            }
        }

        for block in deferred {
            self.new_block_buffer.push_back(block);
        }
        self.process_new_block_buffer();

        let updated_height = self.chain.height();
        if updated_height > local_height {
            log_msg(
                "INFO",
                "CHAIN_SYNC",
                Some(self.node_id.clone()),
                &format!(
                    "并行同步完成，新增 {} 个区块，高度达到 {}。",
                    updated_height - local_height,
                    updated_height
                ),
            );
        }
    }

    fn download_block_ranges_parallel(requests: Vec<(SocketAddr, usize, usize)>) -> Vec<Block> {
        if requests.is_empty() {
            return Vec::new();
        }

        TOKIO_RUNTIME.block_on(async move {
            let tasks = requests.into_iter().map(|(addr, start, end)| async move {
                let payload = serde_json::json!({
                    "cmd": "get_block_range",
                    "data": {
                        "start": start as u64,
                        "end": end as u64,
                    }
                });
                let response = send_json_line_async(addr, payload).await;
                (start, end, response)
            });

            let mut blocks = Vec::new();
            for (_start, _end, resp_opt) in join_all(tasks).await {
                if let Some(resp) = resp_opt {
                    if resp.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                        if let Some(arr) = resp.get("blocks").and_then(Value::as_array) {
                            for block_val in arr {
                                if let Ok(block) =
                                    serde_json::from_value::<Block>(block_val.clone())
                                {
                                    blocks.push(block);
                                }
                            }
                        }
                    }
                }
            }

            blocks
        })
    }

    /// 处理Gossip消息
    fn handle_gossip(&mut self, data: &Value) {
        // 1. 检查是否已经处理过此消息
        if let Some(gossip_id) = data.get("gossip_id").and_then(Value::as_str) {
            if self.has_seen_gossip(gossip_id) {
                return; // 如果见过，则直接返回，避免循环和重复处理
            }
            self.record_seen_gossip_id(gossip_id.to_string());
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
                                                "bidder_addr": [self.advertise_host.clone(), self.port],
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
                "bobtail_proof" | "proof_request" => {
                    // 将共识相关的消息放入内存池等待处理
                    self.mempool.push_back(data.clone());
                }
                "new_block" => {
                    if let Some(block_val) = data.get("block") {
                        match serde_json::from_value::<Block>(block_val.clone()) {
                            Ok(block) => {
                                self.new_block_buffer.push_back(block);
                            }
                            Err(e) => {
                                log_msg(
                                    "WARN",
                                    "BLOCKCHAIN",
                                    Some(self.node_id.clone()),
                                    &format!("无法解析新区块消息: {}", e),
                                );
                            }
                        }
                    }
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

    /// 将消息gossip给一组随机对等节点，使用有限TTL以适配延迟较高的部署网络
    fn gossip(&mut self, mut message: Value, originator: bool) {
        if self.peers.is_empty() {
            return;
        }

        let mut exclude_peer_id: Option<String> = None;
        let mut ttl_remaining = Self::GOSSIP_DEFAULT_TTL;
        if let Value::Object(map) = &mut message {
            if originator {
                let gid = format!(
                    "{}:{}",
                    self.node_id,
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                );
                map.insert(String::from("gossip_id"), Value::from(gid.clone()));
                map.insert(
                    String::from("ttl"),
                    Value::from(Self::GOSSIP_DEFAULT_TTL as u64),
                );
                self.record_seen_gossip_id(gid);
            } else {
                exclude_peer_id = map
                    .get("last_hop")
                    .and_then(Value::as_str)
                    .map(String::from);
                ttl_remaining = map
                    .get("ttl")
                    .and_then(Value::as_u64)
                    .map(|v| v as u32)
                    .unwrap_or(Self::GOSSIP_DEFAULT_TTL);
                if ttl_remaining == 0 {
                    return;
                }
                ttl_remaining = ttl_remaining.saturating_sub(1);
                map.insert(String::from("ttl"), Value::from(ttl_remaining as u64));
            }
            map.insert(String::from("last_hop"), Value::from(self.node_id.clone()));
        } else {
            return;
        }

        if !originator && ttl_remaining == 0 {
            return;
        }

        let mut candidates: Vec<(String, SocketAddr)> = self
            .peers
            .iter()
            .map(|(id, addr)| (id.clone(), *addr))
            .collect();
        if let Some(exclude) = exclude_peer_id {
            let filtered: Vec<(String, SocketAddr)> = candidates
                .iter()
                .filter(|(peer_id, _)| peer_id != &exclude)
                .cloned()
                .collect();
            if !filtered.is_empty() {
                candidates = filtered;
            }
        }
        if candidates.is_empty() {
            return;
        }

        candidates.shuffle(&mut rand::thread_rng());
        let fanout = std::cmp::max(1, std::cmp::min(candidates.len(), Self::GOSSIP_FANOUT));
        for (_, addr) in candidates.into_iter().take(fanout) {
            let _ = send_json_line_without_response(
                addr,
                &serde_json::json!({"cmd": "gossip", "data": message.clone()}),
            );
        }
    }

    /// 处理内存池中的消息
    fn process_mempool(&mut self) {
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
                            let proof_hash = proof.proof_hash.clone();
                            let miner_id = proof.node_id.clone();
                            self.proof_pool
                                .entry(height)
                                .or_default()
                                .entry(miner_id)
                                .or_insert(proof);
                            if let Some(pending) = self.outstanding_proof_requests.get_mut(&height)
                            {
                                pending.remove(&proof_hash);
                                if pending.is_empty() {
                                    self.outstanding_proof_requests.remove(&height);
                                }
                            }
                            self.on_proof_pool_updated(height);
                        }
                    }
                }
                Some("proof_request") => {
                    let requested: Vec<String> = msg
                        .get("proof_hashes")
                        .and_then(Value::as_array)
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    if requested.is_empty() {
                        return;
                    }
                    if let Some(pool) = self.proof_pool.get(&height) {
                        let mut found: Vec<BobtailProof> = Vec::new();
                        for hash in requested {
                            if let Some(proof) =
                                pool.values().find(|p| p.proof_hash == hash).cloned()
                            {
                                found.push(proof);
                            }
                        }
                        for proof in found {
                            log_msg(
                                "DEBUG",
                                "CONSENSUS",
                                Some(self.node_id.clone()),
                                &format!(
                                    "收到证明请求，重播高度 {} 的证明 {}",
                                    height, proof.proof_hash
                                ),
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
                }
                _ => {}
            }
        }
    }

    fn handle_get_block_range(&self, data: &Value) -> CommandResponse {
        let start = data.get("start").and_then(Value::as_u64).unwrap_or(0) as usize;
        let end = data
            .get("end")
            .and_then(Value::as_u64)
            .map(|v| v as usize)
            .unwrap_or(start);

        if start == 0 || start > end {
            return CommandResponse {
                ok: false,
                error: Some(String::from("invalid_range")),
                extra: HashMap::new(),
            };
        }

        let span = end - start + 1;
        if span > Self::MAX_BLOCK_RANGE {
            return CommandResponse {
                ok: false,
                error: Some(String::from("range_too_large")),
                extra: HashMap::new(),
            };
        }

        if start > self.chain.blocks.len() {
            return CommandResponse {
                ok: true,
                error: None,
                extra: HashMap::new(),
            };
        }

        let start_idx = start.saturating_sub(1);
        let end_idx = std::cmp::min(end, self.chain.blocks.len());
        let blocks_slice = &self.chain.blocks[start_idx..end_idx];
        let blocks_json: Vec<Value> = blocks_slice
            .iter()
            .cloned()
            .map(|block| serde_json::to_value(block).unwrap_or(Value::Null))
            .collect();
        let mut extra = HashMap::new();
        extra.insert(String::from("blocks"), Value::from(blocks_json));
        CommandResponse {
            ok: true,
            error: None,
            extra,
        }
    }

    /// 处理新区块缓冲区
    fn process_new_block_buffer(&mut self) {
        let mut pending = std::mem::take(&mut self.new_block_buffer);
        let mut progress = true;

        while progress {
            progress = false;
            let mut next_round = VecDeque::new();

            while let Some(block) = pending.pop_front() {
                match self.try_process_block(block) {
                    BlockHandlingResult::Accepted => {
                        progress = true;
                    }
                    BlockHandlingResult::Deferred(block) => {
                        next_round.push_back(*block);
                    }
                    BlockHandlingResult::Ignored => {}
                }
            }

            pending = next_round;
        }

        self.new_block_buffer = pending;
        let current_height = self.chain.height();
        self.new_block_buffer
            .retain(|block| block.height as usize > current_height);
    }

    fn try_process_block(&mut self, block: Block) -> BlockHandlingResult {
        self.accept_block(block)
    }

    /// 处理挖矿线程上报的证明
    fn drain_mined_proofs(&mut self) {
        while let Ok((height, proof)) = self.mined_proof_rx.try_recv() {
            if height < self.chain.height() + 1 {
                continue; // 已经过期的证明
            }

            let pool = self.proof_pool.entry(height).or_default();
            let mut should_broadcast = false;
            match pool.entry(proof.node_id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(proof.clone());
                    should_broadcast = true;
                }
                Entry::Occupied(mut entry) => {
                    if proof.proof_hash < entry.get().proof_hash {
                        entry.insert(proof.clone());
                        should_broadcast = true;
                    }
                }
            }

            if should_broadcast {
                log_msg(
                    "DEBUG",
                    "MINER",
                    Some(self.node_id.clone()),
                    &format!("高度 {} 获得新的本地证明 {}", height, proof.proof_hash),
                );
                self.gossip(
                    serde_json::json!({
                        "type": "bobtail_proof",
                        "height": height,
                        "proof": proof,
                    }),
                    true,
                );
                self.on_proof_pool_updated(height);
            }
        }
    }

    /// 确保当前高度的挖矿线程正在运行
    fn ensure_mining_thread(&mut self, height: usize) {
        if self.current_mining_height == Some(height) {
            return;
        }

        self.stop_mining_thread();

        let miner = self.miner.clone();
        let seed = self.chain.last_hash();
        let storage_root = self.storage_manager.get_storage_root();
        let file_roots = self.storage_manager.get_file_roots();
        let num_files = self.storage_manager.get_num_files();
        let broadcast_threshold = self.broadcast_threshold.clone();
        let tx = self.mined_proof_tx.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_flag = Arc::clone(&stop_flag);
        let mining_window = self.mining_window_size;
        let node_id = self.node_id.clone();

        match thread::Builder::new()
            .name(format!("mining-{}-{}", node_id, height))
            .spawn(move || {
                let mut next_start = 0u64;
                let mut best_seen: Option<BigUint> = None;
                while !thread_flag.load(Ordering::SeqCst) {
                    if mining_window == 0 || next_start == u64::MAX {
                        break;
                    }
                    let proof_opt = with_cpu_heavy_limit(|| {
                        miner.mine_window(
                            &seed,
                            &storage_root,
                            &file_roots,
                            num_files,
                            next_start,
                            mining_window,
                        )
                    });
                    if thread_flag.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Some(proof) = proof_opt {
                        if let Some(hash_val) =
                            BigUint::parse_bytes(proof.proof_hash.as_bytes(), 16)
                        {
                            if hash_val <= broadcast_threshold
                                && best_seen.as_ref().is_none_or(|prev| hash_val < *prev)
                            {
                                best_seen = Some(hash_val);
                                if tx.send((height, proof)).is_err() {
                                    break;
                                }
                            }
                        }
                    }

                    let new_start = next_start.saturating_add(mining_window);
                    if new_start == next_start {
                        break;
                    }
                    next_start = new_start;
                }
            }) {
            Ok(handle) => {
                log_msg(
                    "DEBUG",
                    "MINER",
                    Some(self.node_id.clone()),
                    &format!("启动高度 {} 的挖矿线程", height),
                );
                self.mining_stop_flag = Some(stop_flag);
                self.mining_thread = Some(handle);
                self.current_mining_height = Some(height);
            }
            Err(e) => {
                log_msg(
                    "ERROR",
                    "MINER",
                    Some(self.node_id.clone()),
                    &format!("无法启动挖矿线程: {}", e),
                );
                self.mining_stop_flag = None;
                self.mining_thread = None;
                self.current_mining_height = None;
            }
        }
    }

    /// 停止当前的挖矿线程
    fn stop_mining_thread(&mut self) {
        if let Some(flag) = self.mining_stop_flag.take() {
            flag.store(true, Ordering::SeqCst);
        }
        if let Some(handle) = self.mining_thread.take() {
            if handle.join().is_err() {
                log_msg(
                    "WARN",
                    "MINER",
                    Some(self.node_id.clone()),
                    "挖矿线程 join 失败",
                );
            }
        }
        self.current_mining_height = None;
    }

    /// 证明池发生变化时尝试完成共识
    fn on_proof_pool_updated(&mut self, height: usize) {
        self.evaluate_consensus_for_height(height);
    }

    /// 检查某个高度的证明池是否满足共识条件
    fn evaluate_consensus_for_height(&mut self, height: usize) {
        if self.election_concluded_for.contains(&height) {
            return;
        }
        if self.bobtail_k == 0 {
            return;
        }

        let Some(pool) = self.proof_pool.get(&height) else {
            return;
        };
        if pool.len() < self.bobtail_k {
            return;
        }

        let mut proofs: Vec<BobtailProof> = pool.values().cloned().collect();
        proofs.sort_by(|a, b| a.proof_hash.cmp(&b.proof_hash));
        let selected = proofs[..self.bobtail_k].to_vec();
        let hash_values: Option<Vec<BigUint>> = selected
            .iter()
            .map(|p| BigUint::parse_bytes(p.proof_hash.as_bytes(), 16))
            .collect();
        let Some(values) = hash_values else {
            return;
        };

        let total = values
            .into_iter()
            .fold(BigUint::from(0u32), |acc, x| acc + x);
        let avg_hash = &total / BigUint::from(self.bobtail_k as u64);

        if avg_hash > self.difficulty_threshold {
            return;
        }

        self.stop_mining_thread();
        let leader_id = selected[0].node_id.clone();
        self.election_concluded_for.insert(height);

        if leader_id == self.node_id {
            log_msg(
                "INFO",
                "CONSENSUS",
                Some(self.node_id.clone()),
                &format!(
                    "高度 {} 的最低证明集合已满足难度阈值，由本节点负责出块。",
                    height
                ),
            );
            self.create_block(height, selected);
        } else {
            log_msg(
                "INFO",
                "CONSENSUS",
                Some(self.node_id.clone()),
                &format!(
                    "高度 {} 的最低证明集合已满足难度阈值，等待领导者 {} 广播新区块。",
                    height, leader_id
                ),
            );
        }
    }

    /// 尝试进行共识
    fn attempt_consensus(&mut self) {
        self.process_new_block_buffer();

        // 如果没有存储文件，则不参与共识
        if self.storage_manager.get_num_files() == 0 {
            self.stop_mining_thread();
            return;
        }
        if self.bobtail_k == 0 {
            return;
        }

        let height = self.chain.height() + 1;
        if self.election_concluded_for.contains(&height) {
            self.stop_mining_thread();
            return;
        }

        self.ensure_mining_thread(height);
        self.evaluate_consensus_for_height(height);
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
                    if pending_rounds.is_empty() && pkg_obj.get("final_fold").is_none() {
                        log_msg(
                            "WARN",
                            "CONSENSUS",
                            Some(self.node_id.clone()),
                            &format!("节点 {} 文件 {} 未提供任何待验证的折叠轮次。", nid, fid),
                        );
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
                        } else {
                            log_msg(
                                "DEBUG",
                                "CONSENSUS",
                                Some(self.node_id.clone()),
                                &format!("dPDP 证明验证Pass：节点 {} 文件 {}。", nid, fid),
                            );
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
            proofs_merkle_tree,
            dpdp_challenges,
            dpdp_proofs,
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

        // 领导者首先更新自己的链，避免等待gossip反馈
        let gossip_block = new_block.clone();
        if !matches!(self.accept_block(new_block), BlockHandlingResult::Accepted) {
            log_msg(
                "ERROR",
                "BLOCKCHAIN",
                Some(self.node_id.clone()),
                &format!("领导者在高度 {} 创建区块失败", height),
            );
            return;
        }

        // 将新区块gossip出去
        self.gossip(
            serde_json::json!({
                "type": "new_block",
                "height": height,
                "block": gossip_block,
            }),
            true,
        );
    }

    fn register_known_block(&mut self, block: &Block) {
        let hash = block.header_hash();
        self.known_blocks
            .entry(hash)
            .or_insert_with(|| block.clone());
    }

    fn collect_branch(&self, block: &Block) -> Result<(usize, Vec<Block>), BranchBuildError> {
        let mut branch = Vec::new();
        let mut current = block.clone();
        let mut visited = HashSet::new();
        let genesis_hash = h_join(["genesis"]);

        loop {
            let hash = current.header_hash();
            if !visited.insert(hash.clone()) {
                return Err(BranchBuildError::Invalid);
            }

            branch.push(current.clone());
            let parent_hash = current.prev_hash.clone();

            if parent_hash == genesis_hash {
                branch.reverse();
                return Ok((0, branch));
            }

            if let Some((idx, parent_block)) = self
                .chain
                .blocks
                .iter()
                .enumerate()
                .rev()
                .find(|(_, b)| b.header_hash() == parent_hash)
            {
                if parent_block.height + 1 != current.height {
                    return Err(BranchBuildError::Invalid);
                }
                branch.reverse();
                return Ok((idx + 1, branch));
            }

            if let Some(parent_block) = self.known_blocks.get(&parent_hash) {
                if parent_block.height + 1 != current.height {
                    return Err(BranchBuildError::Invalid);
                }
                current = parent_block.clone();
                continue;
            }

            return Err(BranchBuildError::MissingAncestor);
        }
    }

    fn apply_branch(
        &mut self,
        prefix_len: usize,
        branch: Vec<Block>,
        previous_height: usize,
        current_work: &BigUint,
        candidate_work: &BigUint,
    ) {
        let is_reorg = prefix_len < previous_height;

        self.stop_mining_thread();

        if is_reorg {
            self.storage_manager.rollback_to_height(prefix_len);
        }

        while self.chain.blocks.len() > prefix_len {
            self.chain.blocks.pop();
        }

        for block in &branch {
            self.register_known_block(block);
            self.chain.add_block(block.clone(), None);
            self.perform_dpdp_round(block);

            let height = block.height as usize;
            self.proof_pool.remove(&height);
            self.outstanding_proof_requests.remove(&height);
            self.election_concluded_for.insert(height);
        }

        if let Some(tip) = branch.last() {
            let leader_id = tip.leader_id.clone();
            if is_reorg {
                log_msg(
                    "INFO",
                    "BLOCKCHAIN",
                    Some(self.node_id.clone()),
                    &format!(
                        "检测到高度 {} 的分叉，切换至来自 {} 的区块。总聚合工作量 {} -> {}",
                        tip.height, leader_id, current_work, candidate_work
                    ),
                );
            } else {
                log_msg(
                    "INFO",
                    "BLOCKCHAIN",
                    Some(self.node_id.clone()),
                    &format!("接受了来自 {} 的区块 {}", leader_id, tip.height),
                );
            }
        }
    }

    /// 接受一个新区块并更新本地区块链状态
    fn accept_block(&mut self, block: Block) -> BlockHandlingResult {
        let block_hash = block.header_hash();
        self.register_known_block(&block);

        if self
            .chain
            .blocks
            .iter()
            .any(|existing| existing.header_hash() == block_hash)
        {
            return BlockHandlingResult::Ignored;
        }

        let (prefix_len, branch) = match self.collect_branch(&block) {
            Ok(result) => result,
            Err(BranchBuildError::MissingAncestor) => {
                return BlockHandlingResult::Deferred(Box::new(block));
            }
            Err(BranchBuildError::Invalid) => {
                self.known_blocks.remove(&block_hash);
                return BlockHandlingResult::Ignored;
            }
        };

        if branch.is_empty() {
            return BlockHandlingResult::Ignored;
        }

        let previous_height = self.chain.height();
        if prefix_len > previous_height {
            return BlockHandlingResult::Ignored;
        }

        let current_work = Self::compute_chain_work(&self.chain.blocks);
        let prefix_work = Self::compute_chain_work(&self.chain.blocks[..prefix_len]);
        let branch_work = Self::compute_chain_work(&branch);
        let mut candidate_work = prefix_work;
        candidate_work += branch_work;

        let extends_tip = prefix_len == previous_height;
        if !extends_tip && candidate_work <= current_work {
            return BlockHandlingResult::Ignored;
        }

        self.apply_branch(
            prefix_len,
            branch,
            previous_height,
            &current_work,
            &candidate_work,
        );

        BlockHandlingResult::Accepted
    }

    fn block_average_proof(block: &Block) -> Option<BigUint> {
        if block.body.selected_k_proofs.is_empty() {
            return None;
        }

        let mut total = BigUint::zero();
        for summary in &block.body.selected_k_proofs {
            let value = BigUint::parse_bytes(summary.proof_hash.as_bytes(), 16)?;
            total += value;
        }

        let divisor = BigUint::from(block.body.selected_k_proofs.len() as u64);
        Some(total / divisor)
    }

    fn block_work(block: &Block) -> Option<BigUint> {
        let avg = Self::block_average_proof(block)?;
        let target = BigUint::parse_bytes(block.bobtail_target.as_bytes(), 16)?;
        Some(target.checked_sub(&avg).unwrap_or_else(BigUint::zero))
    }

    fn compute_chain_work(blocks: &[Block]) -> BigUint {
        let mut total = BigUint::zero();
        for block in blocks {
            if let Some(work) = Self::block_work(block) {
                total += work;
            }
        }
        total
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
            let (chunks, tags) = match self.storage_manager.get_file_data_for_proof(fid) {
                Ok(data) => data,
                Err(FileDataError::Incomplete { missing_indices }) => {
                    log_msg(
                        "WARN",
                        "dPDP_PROVE",
                        Some(self.node_id.clone()),
                        &format!(
                            "文件 {} 数据缺失，跳过证明并请求补发缺失块 {:?}。",
                            fid, missing_indices
                        ),
                    );
                    self.request_missing_chunks(fid, &missing_indices);
                    continue;
                }
                Err(FileDataError::Expired) => {
                    continue;
                }
                Err(FileDataError::NotFound) => {
                    log_msg(
                        "DEBUG",
                        "dPDP_PROVE",
                        Some(self.node_id.clone()),
                        &format!("文件 {} 的数据不可用，跳过证明。", fid),
                    );
                    continue;
                }
            };
            let challenge_len = self
                .storage_manager
                .challenge_size_for(fid)
                .unwrap_or_else(|| tags.len().max(1));
            let (challenge, round_result) = with_cpu_heavy_limit(|| {
                let (proof, challenge, contributions) = self.prover.prove(
                    fid,
                    &chunks,
                    &tags,
                    &accepted_block.prev_hash,
                    (accepted_block.timestamp / 1_000_000_000) as u64,
                    Some(challenge_len),
                );
                let round_salt =
                    format!("{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
                let result = self.storage_manager.process_round(
                    fid,
                    accepted_block,
                    &proof,
                    &challenge,
                    &contributions,
                    &round_salt,
                );
                (challenge, result)
            });
            let entries: Vec<ChallengeEntry> = challenge
                .iter()
                .map(|(i, v)| ChallengeEntry(*i, v.to_string()))
                .collect();
            challenges_by_file.insert(fid.clone(), entries);

            if let Some(result) = round_result {
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
                .map(hex::encode)
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

        let released = self.storage_manager.cleanup_completed_files();
        for (fid, freed_bytes) in released {
            log_msg(
                "INFO",
                "STORE",
                Some(self.node_id.clone()),
                &format!(
                    "文件 {} 的存储周期已完成，自动释放空间 {} 字节。",
                    fid, freed_bytes
                ),
            );
        }
    }
}

/// 解析 "announce" 命令的数据
fn parse_announce(data: &Value) -> Option<(String, SocketAddr)> {
    let node_id = data.get("node_id")?.as_str()?.to_string();
    let host = data.get("host")?.as_str()?;
    let port = data.get("port")?.as_u64()? as u16;
    Some((node_id, SocketAddr::new(host.parse().ok()?, port)))
}

/// 异步发送JSON行数据，并忽略响应结果
pub fn send_json_line_without_response(addr: SocketAddr, payload: &Value) -> bool {
    let payload_clone = payload.clone();
    TOKIO_RUNTIME.spawn(async move {
        let _ = send_json_line_async(addr, payload_clone).await;
    });
    true
}

/// 同步发送JSON行数据，并等待响应
pub fn send_json_line(addr: SocketAddr, payload: &Value) -> Option<Value> {
    let payload_clone = payload.clone();
    TOKIO_RUNTIME.block_on(send_json_line_async(addr, payload_clone))
}

async fn send_json_line_async(addr: SocketAddr, payload: Value) -> Option<Value> {
    let payload_bytes = serde_json::to_vec(&payload).ok()?;
    let max_attempts = 5usize;
    let connect_timeout = Duration::from_secs(2);
    let write_timeout = Duration::from_secs(8);
    let read_timeout = Duration::from_secs(30);

    for attempt in 0..max_attempts {
        let mut stream = match timeout(connect_timeout, TokioTcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                if attempt + 1 >= max_attempts || !is_retryable_error(err.kind()) {
                    return None;
                }
                tokio_sleep(backoff_duration(attempt)).await;
                continue;
            }
            Err(_) => {
                if attempt + 1 >= max_attempts {
                    return None;
                }
                tokio_sleep(backoff_duration(attempt)).await;
                continue;
            }
        };

        match timeout(write_timeout, stream.write_all(&payload_bytes)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                if attempt + 1 >= max_attempts || !is_retryable_error(err.kind()) {
                    return None;
                }
                tokio_sleep(backoff_duration(attempt)).await;
                continue;
            }
            Err(_) => {
                if attempt + 1 >= max_attempts {
                    return None;
                }
                tokio_sleep(backoff_duration(attempt)).await;
                continue;
            }
        }

        match timeout(write_timeout, stream.write_all(b"\n")).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                if attempt + 1 >= max_attempts || !is_retryable_error(err.kind()) {
                    return None;
                }
                tokio_sleep(backoff_duration(attempt)).await;
                continue;
            }
            Err(_) => {
                if attempt + 1 >= max_attempts {
                    return None;
                }
                tokio_sleep(backoff_duration(attempt)).await;
                continue;
            }
        }

        let mut reader = TokioBufReader::new(stream);
        let mut line = String::new();
        match timeout(read_timeout, reader.read_line(&mut line)).await {
            Ok(Ok(0)) => return None,
            Ok(Ok(_)) => return serde_json::from_str(&line).ok(),
            Ok(Err(err)) => {
                if attempt + 1 >= max_attempts || !is_retryable_error(err.kind()) {
                    return None;
                }
                tokio_sleep(backoff_duration(attempt)).await;
            }
            Err(_) => {
                if attempt + 1 >= max_attempts {
                    return None;
                }
                tokio_sleep(backoff_duration(attempt)).await;
            }
        }
    }

    None
}

fn backoff_duration(attempt: usize) -> Duration {
    Duration::from_millis(200 * (attempt as u64 + 1))
}

fn is_retryable_error(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionRefused
    )
}
