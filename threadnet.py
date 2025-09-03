"""
BPoSt的对等网络（P2P）模拟器层，使用原生线程和套接字实现。

该模块是模拟的“驱动程序”。它定义了P2PNode类，
该类为ServerNode actor赋予了网络自治能力，并协调整个模拟流程。
"""
import json
import socket
from dataclasses import dataclass, is_dataclass, asdict
import threading
import time
import random
from collections import deque, defaultdict
from typing import Dict, List, Tuple, Optional, Any, Set

from actors import ServerNode, Client
from protocol import Blockchain, Block, FileChunk, BobtailProof
from utils import log_msg, h_join

# ---------------------------- P2P 网络基础操作 ----------------------------

def _json_sanitize(obj):
    """
    将对象递归转换为可被 JSON 序列化的安全形式：
    - bytes -> 十六进制字符串
    - dataclass -> asdict 后继续处理
    - set/tuple -> 转 list
    - 递归处理 dict/list/tuple/set
    """
    if obj is None or isinstance(obj, (int, float, str, bool)):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if is_dataclass(obj):
        return _json_sanitize(asdict(obj))
    if isinstance(obj, dict):
        return {str(_json_sanitize(k)): _json_sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_json_sanitize(v) for v in obj]
    # 兜底为字符串
    return str(obj)

def _send_json_line(addr, payload: dict) -> Optional[dict]:
    try:
        with socket.create_connection(addr, timeout=0.8) as s:
            safe_payload = _json_sanitize(payload)
            s.sendall((json.dumps(safe_payload) + "\n").encode("utf-8"))
            data = s.recv(16384).decode("utf-8").strip()
            return json.loads(data) if data else None
    except Exception as e:
        log_msg("WARN", "P2P_NET", None, f"无法连接到 {addr}: {e}")
        return None

# ---------------------------- 自治P2P节点 ----------------------------

class P2PNode(threading.Thread):
    """
    BPoSt网络中的一个自治节点。它将一个ServerNode actor封装起来，
    赋予其网络能力，使其能够发现对等节点、广播消息、管理内存池并参与共识。
    """

    def __init__(self, server_node: ServerNode, host: str, port: int, bootstrap_addr: Optional[Tuple[str, int]] = None, 
                 bobtail_k: int = 3, decision_window_sec: int = 3, 
                 difficulty_threshold: str = "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"):
        super().__init__(daemon=True)
        self.node = server_node
        self.host = host
        self.port = port
        self.addr = (host, port)
        self.bootstrap_addr = bootstrap_addr

        self.peers: Dict[str, Tuple[str, int]] = {}
        self.mempool: deque[Dict[str, Any]] = deque(maxlen=100)
        self.proof_pool: Dict[int, Dict[str, BobtailProof]] = defaultdict(dict)
        self.seen_gossip_ids: Set[str] = set()
        self.chain = Blockchain()

        # 共识参数
        self.bobtail_k = bobtail_k
        self.decision_window_sec = decision_window_sec
        self.difficulty_threshold = int(difficulty_threshold, 16)
        self.last_consensus_trigger: Dict[int, float] = {}

        self._stop_event = threading.Event()
        self._server_socket: Optional[socket.socket] = None

    def run(self):
        if not self._start_server(): return
        self._discover_peers()
        log_msg("INFO", "NODE", self.node.node_id, "进入主共识循环...")
        while not self._stop_event.is_set():
            try:
                self._attempt_consensus()
                time.sleep(random.uniform(1, 2)) # 更频繁地检查共识
            except Exception as e:
                log_msg("ERROR", "NODE", self.node.node_id, f"共识循环错误: {e}")

    def _start_server(self) -> bool:
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(self.addr)
            self._server_socket.listen(50)
            self._server_socket.settimeout(0.5)
            threading.Thread(target=self._accept_connections, daemon=True).start()
            log_msg("INFO", "P2P_NET", self.node.node_id, f"在 {self.host}:{self.port} 上监听")
            return True
        except Exception as e:
            log_msg("CRITICAL", "P2P_NET", self.node.node_id, f"启动服务器失败: {e}")
            return False

    def _accept_connections(self):
        while not self._stop_event.is_set():
            try:
                conn, _ = self._server_socket.accept()
                threading.Thread(target=self._handle_connection, args=(conn,), daemon=True).start()
            except (socket.timeout, OSError):
                continue

    def _handle_connection(self, conn: socket.socket):
        with conn:
            try:
                line = conn.recv(16384).decode('utf-8').strip()
                if not line: return
                msg = json.loads(line)
                cmd, data = msg.get("cmd"), msg.get("data", {})
                response = self._dispatch_command(cmd, data)
                conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
            except (json.JSONDecodeError, IOError): pass

    def _dispatch_command(self, cmd: str, data: dict) -> dict:
        handlers = {"get_peers": self._handle_get_peers, "announce": self._handle_announce, "gossip": self._handle_gossip}
        handler = handlers.get(cmd)
        return handler(data) if handler else {"ok": False, "error": "unknown_command"}

    def _handle_get_peers(self, data: dict) -> dict:
        return {"ok": True, "peers": self.peers}

    def _handle_announce(self, data: dict) -> dict:
        node_id, host, port = data.get("node_id"), data.get("host"), data.get("port")
        if node_id and host and port and node_id != self.node.node_id:
            self.peers[node_id] = (host, int(port))
        return {"ok": True}

    def _handle_gossip(self, data: dict) -> dict:
        gossip_id = data.get("gossip_id")
        if not gossip_id or gossip_id in self.seen_gossip_ids:
            return {"ok": True, "status": "already_seen"}
        self.seen_gossip_ids.add(gossip_id)
        self.mempool.append(data)
        self.gossip(data, originator=False)
        return {"ok": True, "status": "accepted"}

    def _discover_peers(self):
        if not self.bootstrap_addr: 
            log_msg("WARN", "P2P_DISCOVERY", self.node.node_id, "作为引导节点运行。")
            return
        log_msg("INFO", "P2P_DISCOVERY", self.node.node_id, f"联系引导节点 {self.bootstrap_addr}...")
        _send_json_line(self.bootstrap_addr, {"cmd": "announce", "data": {"node_id": self.node.node_id, "host": self.host, "port": self.port}})
        resp = _send_json_line(self.bootstrap_addr, {"cmd": "get_peers", "data": {}})
        if resp and resp.get("ok"):
            new_peers = {node_id: tuple(addr) for node_id, addr in resp.get("peers", {}).items()}
            self.peers.update(new_peers)
            log_msg("INFO", "P2P_DISCOVERY", self.node.node_id, f"发现了 {len(self.peers)} 个初始对等节点。")

    def gossip(self, message_data: dict, originator: bool = True):
        if originator:
            message_data["gossip_id"] = f"{self.node.node_id}:{time.time_ns()}"
            self.seen_gossip_ids.add(message_data["gossip_id"])
        if not self.peers: return
        k = int(len(self.peers) ** 0.5) + 1
        gossip_targets = random.sample(list(self.peers.values()), min(k, len(self.peers)))
        for addr in gossip_targets:
            if addr == self.addr: continue
            _send_json_line(addr, {"cmd": "gossip", "data": message_data})

    def _process_mempool(self):
        processed_chunks = 0
        while self.mempool:
            msg = self.mempool.popleft()
            msg_type = msg.get("type")
            if msg_type == "chunk_upload":
                chunk = FileChunk.from_dict(msg.get("chunk"))
                self.node.receive_chunk(chunk)
                processed_chunks += 1
            elif msg_type == "bobtail_proof":
                proof_data, height = msg.get("proof"), msg.get("height")
                if not proof_data or height is None or height < self.chain.height() + 1: continue
                proof = BobtailProof(**proof_data)
                if proof.node_id == self.node.node_id: continue
                if proof.node_id not in self.proof_pool[height]:
                    self.proof_pool[height][proof.node_id] = proof
                    log_msg("DEBUG", "CONSENSUS", self.node.node_id, f"从 {proof.node_id} 收集到高度 {height} 的证明")
            elif msg_type == "new_block":
                new_block = Block.from_dict(msg.get("block"))
                if new_block.prev_hash == self.chain.last_hash() and new_block.height == self.chain.height() + 1:
                    self.chain.add_block(new_block)
                    log_msg("INFO", "BLOCKCHAIN", self.node.node_id, f"接受了来自 {new_block.leader_id} 的区块 {new_block.height}")
                    # 清理旧的证明池
                    if new_block.height in self.proof_pool: del self.proof_pool[new_block.height]
                else:
                    log_msg("WARN", "BLOCKCHAIN", self.node.node_id, f"拒绝了区块 {new_block.height}")
        if processed_chunks > 0:
            log_msg("INFO", "MEMPOOL", self.node.node_id, f"处理了 {processed_chunks} 个分片。")
            self.node.finalize_initial_commitments()

    def _attempt_consensus(self):
        self._process_mempool()
        if self.node.storage.num_files() == 0: return

        height = self.chain.height() + 1
        seed = self.chain.last_hash()

        # 1. 如果需要，生成并广播自己的证明
        if self.node.node_id not in self.proof_pool[height]:
            log_msg("INFO", "CONSENSUS", self.node.node_id, f"开始为高度 {height} 挖矿...")
            proofs = self.node.mine_bobtail(seed=seed, max_nonce=10000)
            if not proofs: return
            my_proof = proofs[0]
            self.proof_pool[height][self.node.node_id] = my_proof
            self.gossip({"type": "bobtail_proof", "height": height, "proof": my_proof.to_dict()})
            log_msg("SUCCESS", "CONSENSUS", self.node.node_id, f"挖出并广播了高度 {height} 的证明。")
            # 记录第一次广播证明的时间
            self.last_consensus_trigger[height] = time.time()

        # 2. 尝试选举leader并出块
        self._try_elect_leader(height)

    def _try_elect_leader(self, height: int):
        """检查是否可以选举leader并创建区块。"""
        if height <= self.chain.height() or self.node.node_id not in self.proof_pool[height]:
            return

        first_proof_time = self.last_consensus_trigger.get(height, 0)
        if time.time() - first_proof_time < self.decision_window_sec:
            return # 未到决策时间

        log_msg("INFO", "LEADER_ELECTION", self.node.node_id, f"在高度 {height} 开始选举...")
        
        candidate_proofs = list(self.proof_pool.get(height, {}).values())
        if len(candidate_proofs) < self.bobtail_k:
            log_msg("WARN", "LEADER_ELECTION", self.node.node_id, f"证明不足 ({len(candidate_proofs)}/{self.bobtail_k})，无法选举。")
            self.last_consensus_trigger[height] = time.time()
            return

        candidate_proofs.sort(key=lambda p: p.proof_hash)
        selected_proofs = candidate_proofs[:self.bobtail_k]
        
        avg_hash_val = sum(int(p.proof_hash, 16) for p in selected_proofs) // self.bobtail_k

        if avg_hash_val > self.difficulty_threshold:
            log_msg("INFO", "LEADER_ELECTION", self.node.node_id, f"平均哈希值未达到阈值。哈希: {avg_hash_val:x}")
            self.last_consensus_trigger[height] = time.time()
            return

        leader_proof = selected_proofs[0]
        leader_id = leader_proof.node_id
        log_msg("SUCCESS", "LEADER_ELECTION", self.node.node_id, f"选举成功！Leader是 {leader_id}。")

        if leader_id == self.node.node_id:
            self._create_and_broadcast_block(height, selected_proofs)

        self.last_consensus_trigger[height] = time.time() + 9999

    def _create_and_broadcast_block(self, height: int, selected_proofs: List[BobtailProof]):
        """创建并向网络广播一个新区块。"""
        log_msg("SUCCESS", "BLOCKCHAIN", self.node.node_id, f"作为Leader，正在为高度 {height} 创建区块...")
        
        # 从K个获胜证明中收集状态树根和时间树根
        merkle_roots = {p.node_id: p.root for p in selected_proofs}
        time_tree_roots = {p.node_id: p.file_roots for p in selected_proofs}

        new_block = Block(
            height=height,
            prev_hash=self.chain.last_hash(),
            seed=self.chain.last_hash(),
            leader_id=self.node.node_id,
            accum_proof_hash=h_join(*[p.proof_hash for p in selected_proofs]),
            merkle_roots=merkle_roots,
            time_tree_roots=time_tree_roots,
            round_proof_stmt_hash=h_join("round_stmt", str(height)),
            bobtail_k=len(selected_proofs),
            selected_k_proofs=[p.to_dict() for p in selected_proofs]
        )
        self.chain.add_block(new_block)
        log_msg("SUCCESS", "BLOCKCHAIN", self.node.node_id, f"生成并添加了新区块 {height}。")
        self.gossip({"type": "new_block", "block": new_block.to_dict()})

    def stop(self):
        self._stop_event.set()
        if self._server_socket: self._server_socket.close()
        log_msg("INFO", "NODE", self.node.node_id, "节点已停止。")

# ---------------------------- 模拟设置 ----------------------------

@dataclass
class P2PSimConfig:
    num_nodes: int = 10
    num_clients: int = 2
    sim_duration_sec: int = 45
    chunk_size: int = 64
    file_kb: int = 32
    base_port: int = 59100
    bobtail_k: int = 3
    decision_window_sec: int = 4
    difficulty_threshold: str = "0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

def run_p2p_simulation(cfg: P2PSimConfig = None):
    if cfg is None: cfg = P2PSimConfig()
    log_msg("INFO", "SYSTEM", "SIMULATOR", f"开始P2P模拟，持续 {cfg.sim_duration_sec} 秒...")

    nodes: List[P2PNode] = []
    bootstrap_node_addr = (socket.gethostbyname('localhost'), cfg.base_port)

    for i in range(cfg.num_nodes):
        p2p_node = P2PNode(
            server_node=ServerNode(f"node-{i}", store_prob=random.uniform(0.7, 1.0)),
            host="127.0.0.1",
            port=cfg.base_port + i,
            bootstrap_addr=bootstrap_node_addr if i > 0 else None,
            bobtail_k=cfg.bobtail_k,
            decision_window_sec=cfg.decision_window_sec,
            difficulty_threshold=cfg.difficulty_threshold
        )
        nodes.append(p2p_node)
        p2p_node.start()
        time.sleep(0.1)

    log_msg("INFO", "SYSTEM", "SIMULATOR", f"{cfg.num_nodes} 个节点已启动。等待网络稳定...")
    time.sleep(2)

    for i in range(cfg.num_clients):
        client = Client(f"user-{i}", chunk_size=cfg.chunk_size)
        chunks = client.dpdp_setup(bytes(random.getrandbits(8) for _ in range(cfg.file_kb * 1024)))
        log_msg("INFO", "USER", client.client_id, f"文件准备就绪，广播 {len(chunks)} 个分片...")
        contact_node = random.choice(nodes)
        for ch in chunks:
            contact_node.gossip({"type": "chunk_upload", "chunk": ch.to_dict()})
            time.sleep(0.01)

    log_msg("INFO", "SYSTEM", "SIMULATOR", "主模拟正在运行。节点现在是自治的。")
    time.sleep(cfg.sim_duration_sec)

    log_msg("INFO", "SYSTEM", "SIMULATOR", "模拟时间结束。正在停止节点...")
    for n in nodes:
        n.stop()
    time.sleep(1)

    log_msg("INFO", "SYSTEM", "ANALYSIS", "--- 模拟分析 ---")
    final_chains: Dict[str, List[str]] = {}
    for n in nodes:
        chain_summary = [b.header_hash()[:8] for b in n.chain.blocks]
        final_chains[n.node.node_id] = chain_summary
        log_msg("INFO", "SYSTEM", "ANALYSIS",
                f"节点 {n.node.node_id}: 区块链高度={n.chain.height()}, 文件数={n.node.storage.num_files()}, 对等节点数={len(n.peers)}")

    if final_chains:
        sorted_chains = sorted(final_chains.values(), key=len, reverse=True)
        longest_chain = sorted_chains[0]
        consensus = all(longest_chain[:len(c)] == c for c in sorted_chains)
        log_msg("SUCCESS" if consensus else "FAIL", "SYSTEM", "CONSENSUS_CHECK", f"最终链共识: {'达成' if consensus else '失败'}")
