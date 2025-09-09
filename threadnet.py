"""
BPoSt的对等网络（P2P）模拟器层，使用原生线程和套接字实现。

该模块是模拟的“驱动程序”。它定义了P2PNode类，
该类为StorageNode actor赋予了网络自治能力，并协调整个模拟流程。
"""
import json
import socket
import multiprocessing
import threading
import time
import random
from collections import deque, defaultdict
from dataclasses import dataclass, is_dataclass, asdict
from queue import Empty
from typing import Dict, List, Tuple, Optional, Any, Set

from actors import StorageNode, FileOwner
from protocol import Blockchain, Block, FileChunk, BobtailProof
from utils import log_msg, h_join

# ---------------------------- P2P 网络基础操作 ----------------------------

def _json_sanitize(obj):
    """递归地将对象转换为可JSON序列化的形式。"""
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
    return str(obj)

def _send_json_line(addr, payload: dict) -> Optional[dict]:
    try:
        with socket.create_connection(addr, timeout=0.8) as s:
            safe_payload = _json_sanitize(payload)
            s.sendall((json.dumps(safe_payload) + "\n").encode("utf-8"))
            data = s.recv(16384).decode("utf-8").strip()
            return json.loads(data) if data else None
    except Exception:
        return None

# ---------------------------- 自治P2P节点 (多进程) ----------------------------

@dataclass
class P2PSimConfig:
    """P2P模拟的配置参数"""
    num_nodes: int = 20
    num_file_owners: int = 3
    sim_duration_sec: int = 600
    chunk_size: int = 1024
    min_file_kb: int = 2
    max_file_kb: int = 4
    min_storage_nodes: int = 3
    max_storage_nodes: int = 7
    base_port: int = 59000
    bobtail_k: int = 2
    min_storage_kb: int = 512
    max_storage_kb: int = 2048
    bid_wait_sec: int = 10

class P2PNode(multiprocessing.Process):
    """
    BPoSt网络中的一个自治节点，现在作为独立进程运行。
    """

    def __init__(self, server_node: StorageNode, host: str, port: int, bootstrap_addr: Optional[Tuple[str, int]], 
                 bobtail_k: int, stop_event: multiprocessing.Event, report_queue: multiprocessing.Queue):
        super().__init__(daemon=True)
        self.node = server_node
        self.host = host
        self.port = port
        self.addr = (host, port)
        self.bootstrap_addr = bootstrap_addr
        self.report_queue = report_queue

        self.peers: Dict[str, Tuple[str, int]] = {}
        self.mempool: deque[Dict[str, Any]] = deque(maxlen=100)
        self.proof_pool: Dict[int, Dict[str, BobtailProof]] = defaultdict(dict)
        self.seen_gossip_ids: Set[str] = set()
        self.chain = Blockchain()

        self.bobtail_k = bobtail_k
        self.difficulty_threshold = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
        
        # -- 新的、更精细的共识状态变量 --
        # 存储收到的“预准备”信号 {height: {sender_id: (proof_hash_1, ...)}} 
        self.preprepare_signals: Dict[int, Dict[str, Tuple[str, ...]]] = defaultdict(dict)
        # 标记自己是否已发送“预准备”信号 {height: (my_proof_hash_1, ...)}
        self.sent_preprepare_signal_at: Dict[int, Tuple[str, ...]] = {}
        # 用于检测预准备集合是否稳定的状态 {height: frozenset(signals.items())}
        self.last_preprepare_state: Dict[int, Any] = {}
        # 标记某个高度的选举是否已结束 {height}
        self.election_concluded_for: Set[int] = set()

        self._stop_event = stop_event
        self._server_socket: Optional[socket.socket] = None
        
        self.chain_lock: Optional[threading.Lock] = None
        self.mining_thread: Optional[threading.Thread] = None

    def run(self):
        self.chain_lock = threading.Lock()
        if not self._start_server(): return
        self._discover_peers()

        self.mining_thread = threading.Thread(target=self._mining_loop, daemon=True)
        self.mining_thread.start()

        log_msg("DEBUG", "NODE", self.node.node_id, f"进入主循环... (存储容量: {self.node.max_storage // 1024} KB)")
        
        last_report_time = time.time()
        while not self._stop_event.is_set():
            try:
                self._process_mempool()
                if time.time() - last_report_time > 3.0:
                    self._report_status()
                    last_report_time = time.time()
                time.sleep(0.1)
            except Exception as e:
                log_msg("ERROR", "NODE", self.node.node_id, f"主循环错误: {e}")
        
        final_state = {
            "type": "final_state",
            "node_id": self.node.node_id,
            "chain": [h_join(b.header_hash()) for b in self.chain.blocks]
        }
        self.report_queue.put(final_state)
        log_msg("DEBUG", "NODE", self.node.node_id, "进程已停止并报告了最终状态。")

    def _mining_loop(self):
        """专用于挖矿和共识检查的线程循环。"""
        while not self._stop_event.is_set():
            try:
                self._attempt_consensus()
                time.sleep(random.uniform(1, 2))
            except Exception as e:
                log_msg("ERROR", "MINING_THREAD", self.node.node_id, f"挖矿循环错误: {e}")

    def _report_status(self):
        with self.chain_lock:
            height = self.chain.height()
            status = {
                "type": "status_update",
                "node_id": self.node.node_id,
                "chain_height": height,
                "chain_head": h_join(self.chain.last_hash()),
                "peers": len(self.peers),
                "mempool_size": len(self.mempool),
                "proof_pool_size": len(self.proof_pool.get(height + 1, {})),
                "is_mining": self.node.storage.num_files() > 0,
            }
        self.report_queue.put(status)

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
        handlers = {
            "get_peers": self._handle_get_peers, 
            "announce": self._handle_announce, 
            "gossip": self._handle_gossip,
            "inject_gossip": self._handle_inject_gossip,
            "chunk_distribute": self._handle_chunk_distribute,
            "finalize_storage": self._handle_finalize_storage,
        }
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
        
        if data.get("type") == "storage_offer":
            self._handle_storage_offer(data)
        elif data.get("type") in ["bobtail_proof", "preprepare_signal", "new_block"]:
            self.mempool.append(data)

        self.gossip(data, originator=False)
        return {"ok": True, "status": "accepted"}

    def _handle_inject_gossip(self, data: dict) -> dict:
        self.gossip(data, originator=True)
        return {"ok": True, "status": "gossip_initiated"}

    def _handle_storage_offer(self, offer_data: dict):
        if self.node.can_store(offer_data.get("total_size", 0)):
            bid_msg = {
                "cmd": "storage_bid",
                "data": {
                    "type": "storage_bid",
                    "request_id": offer_data.get("request_id"),
                    "bidder_id": self.node.node_id,
                    "bidder_addr": self.addr,
                }
            }
            _send_json_line(tuple(offer_data.get("reply_addr")), bid_msg)

    def _handle_chunk_distribute(self, data: dict) -> dict:
        chunk = FileChunk.from_dict(data.get("chunk"))
        return {"ok": self.node.receive_chunk(chunk)}

    def _handle_finalize_storage(self, data: dict) -> dict:
        self.node.finalize_initial_commitments()
        return {"ok": True}

    def _discover_peers(self):
        if not self.bootstrap_addr: 
            log_msg("DEBUG", "P2P_DISCOVERY", self.node.node_id, "作为引导节点运行。")
            return
        log_msg("DEBUG", "P2P_DISCOVERY", self.node.node_id, f"联系引导节点 {self.bootstrap_addr}...")
        _send_json_line(self.bootstrap_addr, {"cmd": "announce", "data": {"node_id": self.node.node_id, "host": self.host, "port": self.port}})
        resp = _send_json_line(self.bootstrap_addr, {"cmd": "get_peers", "data": {}})
        if resp and resp.get("ok"):
            self.peers.update({nid: tuple(addr) for nid, addr in resp.get("peers", {}).items()})
            log_msg("INFO", "P2P_DISCOVERY", self.node.node_id, f"发现了 {len(self.peers)} 个初始对等节点。")

    def gossip(self, message_data: dict, originator: bool = True):
        if originator:
            message_data["gossip_id"] = f"{self.node.node_id}:{time.time_ns()}"
            self.seen_gossip_ids.add(message_data["gossip_id"])
            log_msg("DEBUG", "GOSSIP", self.node.node_id, f"发起gossip广播: {message_data.get('type')}")

        if not self.peers: return
        # 修改为向所有对等节点广播，确保共识消息的完全同步
        for addr in self.peers.values():
            if addr == self.addr: continue
            _send_json_line(addr, {"cmd": "gossip", "data": message_data})

    def _process_mempool(self):
        try:
            msg = self.mempool.popleft()
        except IndexError:
            return

        msg_type = msg.get("type")
        height = msg.get("height")
        if height is None or height < self.chain.height() + 1: return

        with self.chain_lock:
            if msg_type == "bobtail_proof":
                # 一旦发送了预准备信号，就不再接受新的单个证明
                if height in self.sent_preprepare_signal_at: return
                proof = BobtailProof(**msg.get("proof"))
                if proof.node_id not in self.proof_pool[height]:
                    self.proof_pool[height][proof.node_id] = proof
            
            elif msg_type == "preprepare_signal":
                sender_id, proof_hashes = msg.get("sender_id"), tuple(msg.get("proof_hashes", []))
                if sender_id and proof_hashes:
                    self.preprepare_signals[height][sender_id] = proof_hashes

            elif msg_type == "new_block":
                new_block = Block.from_dict(msg.get("block"))
                if new_block.prev_hash == self.chain.last_hash() and new_block.height == self.chain.height() + 1:
                    self.chain.add_block(new_block)
                    log_msg("INFO", "BLOCKCHAIN", self.node.node_id, f"接受了来自 {new_block.leader_id} 的区块 {new_block.height}")
                    # 清理该高度的所有共识状态
                    for d in [self.proof_pool, self.preprepare_signals, self.sent_preprepare_signal_at, self.last_preprepare_state]:
                        if height in d: del d[height]
                    self.election_concluded_for.add(height)

    def _attempt_consensus(self):
        if self.node.storage.num_files() == 0: return

        with self.chain_lock:
            height = self.chain.height() + 1
            # 如果选举已结束或正在进行，则无需挖矿
            if height in self.election_concluded_for or height in self.sent_preprepare_signal_at:
                pass
            # 否则，进行挖矿
            elif self.node.node_id not in self.proof_pool.get(height, {}):
                seed = self.chain.last_hash()
                proofs = self.node.mine_bobtail(seed=seed, max_nonce=10000)
                if proofs:
                    my_proof = proofs[0]
                    self.proof_pool[height][self.node.node_id] = my_proof
                    log_msg("DEBUG", "CONSENSUS", self.node.node_id, f"为高度 {height} 挖出了一个证明")
                    gossip_msg = {"type": "bobtail_proof", "height": height, "proof": my_proof.to_dict()}
                    # 在锁外进行gossip
                    threading.Thread(target=self.gossip, args=(gossip_msg,)).start()

        # 无论是否挖矿，都尝试推进共识
        with self.chain_lock:
            self._try_elect_leader(self.chain.height() + 1)

    def _try_elect_leader(self, height: int):
        # 此方法应在获取chain_lock后调用
        if height in self.election_concluded_for: return

        # --- 阶段 1: 收集证明 -> 发送“预准备”信号 --- 
        if height not in self.sent_preprepare_signal_at:
            candidate_proofs = list(self.proof_pool.get(height, {}).values())
            if len(candidate_proofs) >= self.bobtail_k:
                candidate_proofs.sort(key=lambda p: p.proof_hash)
                selected_proofs = candidate_proofs[:self.bobtail_k]
                avg_hash_val = sum(int(p.proof_hash, 16) for p in selected_proofs) // self.bobtail_k

                if avg_hash_val <= self.difficulty_threshold:
                    my_proof_set = tuple(sorted([p.proof_hash for p in selected_proofs]))
                    self.sent_preprepare_signal_at[height] = my_proof_set
                    self.preprepare_signals[height][self.node.node_id] = my_proof_set
                    log_msg("INFO", "CONSENSUS", self.node.node_id, f"为高度 {height} 达成预备条件，广播预准备信号")
                    gossip_msg = {"type": "preprepare_signal", "height": height, "sender_id": self.node.node_id, "proof_hashes": my_proof_set}
                    threading.Thread(target=self.gossip, args=(gossip_msg,)).start()
            return # 无论是否发送成功，都返回并等待下一轮检查

        # --- 阶段 2: 收集“预准备”信号 -> 等待集合稳定 ---
        current_signals = self.preprepare_signals.get(height, {})
        # 使用frozenset来创建一个可哈希的、无序的项视图，用于比较状态
        current_state = frozenset(current_signals.items())
        last_state = self.last_preprepare_state.get(height)

        # 如果状态没有变化，并且我们已经收到了一些信号，就认为集合是稳定的
        is_stable = (current_state == last_state and len(current_state) > 0)
        self.last_preprepare_state[height] = current_state
        
        if not is_stable:
            return # 集合尚未稳定，等待更多信号

        # --- 阶段 3: 集合已稳定 -> 计票并选举 --- 
        log_msg("DEBUG", "CONSENSUS", self.node.node_id, f"高度 {height} 的预准备集合已稳定，开始计票")
        
        votes = defaultdict(list)
        for sender_id, proof_hashes_tuple in current_signals.items():
            votes[proof_hashes_tuple].append(sender_id)

        for proof_hashes_tuple, voters in votes.items():
            # 如果某个证明集获得了足够多的票数
            if len(voters) >= self.bobtail_k:
                all_proofs = self.proof_pool.get(height, {})
                # 检查我们本地是否拥有所有获胜所需的证明
                if not all(h in all_proofs for h in proof_hashes_tuple):
                    continue # 如果缺少证明，则跳过，等待gossip同步

                winning_proofs = [p for p in all_proofs.values() if p.proof_hash in proof_hashes_tuple]
                if len(winning_proofs) < self.bobtail_k: continue

                winning_proofs.sort(key=lambda p: p.proof_hash)
                leader_id = winning_proofs[0].node_id

                if self.node.node_id == leader_id:
                    log_msg("SUCCESS", "CONSENSUS", self.node.node_id, f"被选举为高度 {height} 的领导者！正在创建区块...")
                    new_block = Block(
                        height=height,
                        prev_hash=self.chain.last_hash(),
                        seed=self.chain.last_hash(),
                        leader_id=leader_id,
                        time_tree_roots={p.node_id: p.file_roots for p in winning_proofs},
                        selected_k_proofs=[{"node_id": p.node_id, "proof_hash": p.proof_hash} for p in winning_proofs],
                        bobtail_k=self.bobtail_k,
                        bobtail_target=hex(self.difficulty_threshold),
                        accum_proof_hash="placeholder", merkle_roots={}, round_proof_stmt_hash="placeholder",
                        coinbase_splits={p.address: "1" for p in winning_proofs}
                    )
                    gossip_msg = {"type": "new_block", "block": new_block.to_dict()}
                    threading.Thread(target=self.gossip, args=(gossip_msg,)).start()
                
                # 标记此高度选举已完成，防止重复工作
                self.election_concluded_for.add(height)
                return # 选举完成，退出函数

class UserNode(multiprocessing.Process):
    """
    表示网络中的文件所有者，作为独立节点请求存储和管理文件。
    """
    def __init__(self, owner: FileOwner, host: str, port: int, bootstrap_addr: Tuple[str, int],
                 config: P2PSimConfig, stop_event: multiprocessing.Event):
        super().__init__(daemon=True)
        self.owner = owner
        self.host = host
        self.port = port
        self.addr = (host, port)
        self.bootstrap_addr = bootstrap_addr
        self.config = config
        self._stop_event = stop_event
        self._server_socket: Optional[socket.socket] = None
        self.bids: Dict[str, List[dict]] = defaultdict(list)
        self.active_requests: Set[str] = set()

    def run(self):
        if not self._start_server(): return
        log_msg("INFO", "USER_NODE", self.owner.owner_id, f"用户节点已在 {self.host}:{self.port} 启动")
        while not self._stop_event.is_set():
            if not self.active_requests:
                if random.random() < 0.3:
                    self._try_store_file()
            time.sleep(random.uniform(3, 7))
        log_msg("DEBUG", "USER_NODE", self.owner.owner_id, "进程已停止。")

    def _start_server(self) -> bool:
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(self.addr)
            self._server_socket.listen(10)
            self._server_socket.settimeout(0.5)
            threading.Thread(target=self._accept_connections, daemon=True).start()
            return True
        except Exception as e:
            log_msg("CRITICAL", "USER_NODE", self.owner.owner_id, f"启动服务器失败: {e}")
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
                line = conn.recv(8192).decode('utf-8').strip()
                if not line: return
                msg = json.loads(line)
                cmd, data = msg.get("cmd"), msg.get("data", {})
                response = self._dispatch_command(cmd, data)
                conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
            except (json.JSONDecodeError, IOError): pass

    def _dispatch_command(self, cmd: str, data: dict) -> dict:
        if cmd == "storage_bid":
            return self._handle_storage_bid(data)
        return {"ok": False, "error": "unknown_command"}

    def _handle_storage_bid(self, data: dict) -> dict:
        request_id = data.get("request_id")
        if request_id in self.active_requests:
            self.bids[request_id].append(data)
            return {"ok": True, "status": "bid_accepted"}
        return {"ok": False, "error": "request_not_active"}

    def _try_store_file(self):
        num_nodes_required = min(random.randint(self.config.min_storage_nodes, self.config.max_storage_nodes), self.config.num_nodes)
        chunks, _ = self.owner.prepare_storage_request(
            min_size_bytes=self.config.min_file_kb * 1024,
            max_size_bytes=self.config.max_file_kb * 1024,
            num_nodes=num_nodes_required
        )
        if not chunks: return

        total_size = len(chunks) * self.config.chunk_size
        request_id = f"req-{self.owner.file_id}"
        self.active_requests.add(request_id)

        log_msg("INFO", "USER_NODE", self.owner.owner_id, f"为文件 {self.owner.file_id} ({total_size // 1024}KB) 发起存储，需要 {num_nodes_required} 个节点。")

        offer_msg = {
            "type": "storage_offer",
            "request_id": request_id,
            "file_id": self.owner.file_id,
            "total_size": total_size,
            "reply_addr": self.addr
        }
        
        _send_json_line(self.bootstrap_addr, {"cmd": "inject_gossip", "data": offer_msg})

        log_msg("INFO", "USER_NODE", self.owner.owner_id, f"为请求 {request_id} 等待 {self.config.bid_wait_sec} 秒以收集竞标...")
        time.sleep(self.config.bid_wait_sec)

        collected_bids = self.bids.get(request_id, [])
        if len(collected_bids) >= num_nodes_required:
            winners = random.sample(collected_bids, num_nodes_required)
            winning_addrs = [tuple(w['bidder_addr']) for w in winners]
            log_msg("SUCCESS", "USER_NODE", self.owner.owner_id, f"文件 {self.owner.file_id} 的存储竞标完成。")

            for chunk in chunks:
                for addr in winning_addrs:
                    _send_json_line(addr, {"cmd": "chunk_distribute", "data": {"chunk": chunk.to_dict()}})

            for addr in winning_addrs:
                _send_json_line(addr, {"cmd": "finalize_storage", "data": {"file_id": self.owner.file_id}})
        else:
            log_msg("WARN", "USER_NODE", self.owner.owner_id, f"文件 {self.owner.file_id} 的存储请求失败。竞标数量不足。")

        if request_id in self.bids: del self.bids[request_id]
        self.active_requests.remove(request_id)

def run_p2p_simulation(config: P2PSimConfig):
    """运行BPoSt P2P网络的全功能模拟。"""
    log_msg("INFO", "SIMULATOR", "MAIN", f"正在使用配置启动模拟: {config}")

    manager = multiprocessing.Manager()
    report_queue = manager.Queue()
    final_chain_reports = manager.dict()
    
    stop_events = []
    all_procs = []
    
    bootstrap_addr = ("localhost", config.base_port)
    current_port = config.base_port

    p2p_nodes: List[P2PNode] = []
    for i in range(config.num_nodes):
        node_id = f"S{i}"
        port = current_port
        current_port += 1
        node_capacity = random.randint(config.min_storage_kb, config.max_storage_kb) * 1024
        storage_node = StorageNode(node_id=node_id, chunk_size=config.chunk_size, max_storage=node_capacity)
        
        stop_event = manager.Event()
        p2p_node = P2PNode(server_node=storage_node, host="localhost", port=port, 
                             bootstrap_addr=bootstrap_addr if i > 0 else None, 
                             bobtail_k=config.bobtail_k, 
                             stop_event=stop_event, report_queue=report_queue)
        p2p_nodes.append(p2p_node)
        stop_events.append(stop_event)
        all_procs.append(p2p_node)

    user_nodes: List[UserNode] = []
    for i in range(config.num_file_owners):
        owner_id = f"U{i}"
        port = current_port
        current_port += 1
        file_owner = FileOwner(owner_id, config.chunk_size)
        
        stop_event = manager.Event()
        user_node = UserNode(owner=file_owner, host="localhost", port=port,
                             bootstrap_addr=bootstrap_addr,
                             config=config,
                             stop_event=stop_event)
        user_nodes.append(user_node)
        stop_events.append(stop_event)
        all_procs.append(user_node)

    for proc in all_procs:
        proc.start()
        time.sleep(0.05)

    log_msg("INFO", "SIMULATOR", "MAIN", f"已启动 {len(p2p_nodes)} 个存储节点和 {len(user_nodes)} 个用户节点。")
    log_msg("INFO", "SIMULATOR", "MAIN", f"共识和存储模拟将运行 {config.sim_duration_sec} 秒...")
    
    reporter_stop_event = threading.Event()
    # ... (状态报告线程保持不变) ...

    try:
        time.sleep(config.sim_duration_sec)
    except KeyboardInterrupt:
        log_msg("INFO", "SIMULATOR", "MAIN", "检测到手动中断。正在停止...")

    log_msg("INFO", "SIMULATOR", "MAIN", "模拟时间结束。正在停止节点并分析结果...")
    for event in stop_events:
        event.set()
    for proc in all_procs:
        proc.join(timeout=5)

    # ... (最终分析逻辑保持不变) ...
    log_msg("INFO", "SIMULATOR", "MAIN", "模拟结束。")
