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
    num_nodes: int = 10
    num_file_owners: int = 3
    sim_duration_sec: int = 60
    chunk_size: int = 256
    min_file_kb: int = 64
    max_file_kb: int = 256
    min_storage_nodes: int = 3
    max_storage_nodes: int = 7
    base_port: int = 59000
    bobtail_k: int = 3
    min_storage_kb: int = 512
    max_storage_kb: int = 2048
    bid_wait_sec: int = 5

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
        self.difficulty_threshold = int("00000000000000ffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
        
        self.ready_signals: Dict[int, Dict[str, Tuple[str, ...]]] = defaultdict(dict)
        self.sent_ready_signal: Set[int] = set()

        self._stop_event = stop_event
        self._server_socket: Optional[socket.socket] = None
        
        # 锁和线程将在run()方法中为每个进程单独初始化，以避免序列化错误
        self.chain_lock: Optional[threading.Lock] = None
        self.mining_thread: Optional[threading.Thread] = None

    def run(self):
        # 在进程启动后初始化锁，以避免序列化问题
        self.chain_lock = threading.Lock()

        if not self._start_server(): return
        self._discover_peers()

        # 启动并行的挖矿线程
        self.mining_thread = threading.Thread(target=self._mining_loop, daemon=True)
        self.mining_thread.start()

        log_msg("DEBUG", "NODE", self.node.node_id, f"进入主循环... (存储容量: {self.node.max_storage // 1024} KB)")
        
        last_report_time = time.time()
        while not self._stop_event.is_set():
            try:
                # 主循环现在只处理mempool和报告状态
                self._process_mempool()
                
                # 定期报告实时状态
                if time.time() - last_report_time > 3.0:
                    self._report_status()
                    last_report_time = time.time()

                time.sleep(0.1) # 短暂休眠以避免CPU空转
            except Exception as e:
                log_msg("ERROR", "NODE", self.node.node_id, f"主循环错误: {e}")
        
        # 模拟结束，报告最终状态
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
                time.sleep(random.uniform(1, 2)) # 挖矿/共识尝试之间的间隔
            except Exception as e:
                log_msg("ERROR", "MINING_THREAD", self.node.node_id, f"挖矿循环错误: {e}")

    def _report_status(self):
        """将节点的当前状态放入报告队列。"""
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
        elif data.get("type") in ["bobtail_proof", "ready_signal", "new_block"]:
            self.mempool.append(data)

        self.gossip(data, originator=False)
        return {"ok": True, "status": "accepted"}

    def _handle_inject_gossip(self, data: dict) -> dict:
        self.gossip(data, originator=True)
        return {"ok": True, "status": "gossip_initiated"}

    def _handle_storage_offer(self, offer_data: dict):
        if self.node.can_store(offer_data.get("total_size", 0)):
            log_msg("DEBUG", "STORAGE_BID", self.node.node_id, f"容量充足，发送竞标。")
            bid_msg = {
                "cmd": "storage_bid",
                "data": {
                    "type": "storage_bid",
                    "request_id": offer_data.get("request_id"),
                    "bidder_id": self.node.node_id,
                    "bidder_addr": self.addr,
                }
            }
            reply_addr = tuple(offer_data.get("reply_addr"))
            _send_json_line(reply_addr, bid_msg)

    def _handle_chunk_distribute(self, data: dict) -> dict:
        chunk = FileChunk.from_dict(data.get("chunk"))
        success = self.node.receive_chunk(chunk)
        return {"ok": success}

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
            new_peers = {node_id: tuple(addr) for node_id, addr in resp.get("peers", {}).items()}
            self.peers.update(new_peers)
            log_msg("INFO", "P2P_DISCOVERY", self.node.node_id, f"发现了 {len(self.peers)} 个初始对等节点。")

    def gossip(self, message_data: dict, originator: bool = True):
        if originator:
            message_data["gossip_id"] = f"{self.node.node_id}:{time.time_ns()}"
            self.seen_gossip_ids.add(message_data["gossip_id"])
            log_msg("DEBUG", "GOSSIP", self.node.node_id, f"发起gossip广播: {message_data.get('type')}")

        if not self.peers: return
        k = int(len(self.peers) ** 0.5) + 1
        gossip_targets = random.sample(list(self.peers.values()), min(k, len(self.peers)))
        for addr in gossip_targets:
            if addr == self.addr: continue
            _send_json_line(addr, {"cmd": "gossip", "data": message_data})

    def _process_mempool(self):
        try:
            msg = self.mempool.popleft()
        except IndexError:
            return # Mempool为空

        msg_type = msg.get("type")
        
        with self.chain_lock:
            if msg_type == "bobtail_proof":
                proof_data, height = msg.get("proof"), msg.get("height")
                if not proof_data or height is None or height < self.chain.height() + 1: return
                proof = BobtailProof(**proof_data)
                if proof.node_id == self.node.node_id: return
                if proof.node_id not in self.proof_pool[height]:
                    self.proof_pool[height][proof.node_id] = proof
                    log_msg("DEBUG", "CONSENSUS", self.node.node_id, f"收到并存储了来自 {proof.node_id} 的高度 {height} 的证明")
            elif msg_type == "ready_signal":
                height, sender_id = msg.get("height"), msg.get("sender_id")
                proof_hashes = tuple(msg.get("proof_hashes", []))
                if not height or not sender_id or not proof_hashes or height < self.chain.height() + 1: return
                if sender_id not in self.ready_signals[height]:
                    self.ready_signals[height][sender_id] = proof_hashes
                    log_msg("DEBUG", "CONSENSUS", self.node.node_id, f"收到并存储了来自 {sender_id} 的高度 {height} 的就绪信号")
            elif msg_type == "new_block":
                new_block = Block.from_dict(msg.get("block"))
                if new_block.prev_hash == self.chain.last_hash() and new_block.height == self.chain.height() + 1:
                    self.chain.add_block(new_block)
                    log_msg("INFO", "BLOCKCHAIN", self.node.node_id, f"接受了来自 {new_block.leader_id} 的区块 {new_block.height}")
                    if new_block.height in self.proof_pool: del self.proof_pool[new_block.height]
                    if new_block.height in self.ready_signals: del self.ready_signals[new_block.height]
                    if new_block.height in self.sent_ready_signal: self.sent_ready_signal.remove(new_block.height)
                else:
                    log_msg("WARN", "BLOCKCHAIN", self.node.node_id, f"拒绝了区块 {new_block.height} (PrevHash: {h_join(new_block.prev_hash)}, MyLastHash: {h_join(self.chain.last_hash())})")

    def _attempt_consensus(self):
        if self.node.storage.num_files() == 0: return

        with self.chain_lock:
            height = self.chain.height() + 1
            seed = self.chain.last_hash()
            should_mine = self.node.node_id not in self.proof_pool.get(height, {}) and height not in self.sent_ready_signal
        
        if should_mine:
            proofs = self.node.mine_bobtail(seed=seed, max_nonce=10000)
            if proofs:
                my_proof = proofs[0]
                gossip_msg = None
                with self.chain_lock:
                    if self.chain.height() + 1 == height and self.node.node_id not in self.proof_pool[height]:
                        self.proof_pool[height][self.node.node_id] = my_proof
                        log_msg("DEBUG", "CONSENSUS", self.node.node_id, f"为高度 {height} 挖出了一个证明")
                        gossip_msg = {"type": "bobtail_proof", "height": height, "proof": my_proof.to_dict()}
                if gossip_msg:
                    self.gossip(gossip_msg)

        with self.chain_lock:
            self._try_elect_leader(self.chain.height() + 1)

    def _try_elect_leader(self, height: int):
        # 注意: 此方法应在获取chain_lock后调用
        if height <= self.chain.height() or height in self.sent_ready_signal: return

        candidate_proofs = list(self.proof_pool.get(height, {}).values())
        if len(candidate_proofs) >= self.bobtail_k:
            candidate_proofs.sort(key=lambda p: p.proof_hash)
            selected_proofs = candidate_proofs[:self.bobtail_k]
            avg_hash_val = sum(int(p.proof_hash, 16) for p in selected_proofs) // self.bobtail_k

            if avg_hash_val <= self.difficulty_threshold:
                winning_hashes = tuple(sorted([p.proof_hash for p in selected_proofs]))
                self.sent_ready_signal.add(height)
                self.ready_signals[height][self.node.node_id] = winning_hashes
                log_msg("DEBUG", "CONSENSUS", self.node.node_id, f"为高度 {height} 达成局部共识，广播就绪信号")
                gossip_msg = {"type": "ready_signal", "height": height, "sender_id": self.node.node_id, "proof_hashes": winning_hashes}
                # 在锁外gossip
                threading.Thread(target=self.gossip, args=(gossip_msg,)).start()


        if not self.ready_signals.get(height): return

        votes = defaultdict(list)
        for sender_id, proof_hashes_tuple in self.ready_signals[height].items():
            votes[proof_hashes_tuple].append(sender_id)

        for proof_hashes_tuple, voters in votes.items():
            if len(voters) >= self.bobtail_k:
                all_proofs_at_height = self.proof_pool.get(height, {})
                winning_proofs = [p for p in all_proofs_at_height.values() if p.proof_hash in proof_hashes_tuple]
                if len(winning_proofs) < self.bobtail_k: continue

                winning_proofs.sort(key=lambda p: p.proof_hash)
                leader_id = winning_proofs[0].node_id

                if self.node.node_id == leader_id:
                    log_msg("SUCCESS", "CONSENSUS", self.node.node_id, f"被选举为高度 {height} 的领导者！正在创建区块...")
                    time_tree_roots = {p.node_id: p.file_roots for p in winning_proofs}
                    selected_proofs_summary = [{"node_id": p.node_id, "proof_hash": p.proof_hash} for p in winning_proofs]
                    new_block = Block(height=height, prev_hash=self.chain.last_hash(), seed=self.chain.last_hash(), leader_id=leader_id, time_tree_roots=time_tree_roots, selected_k_proofs=selected_proofs_summary, bobtail_k=self.bobtail_k, bobtail_target=hex(self.difficulty_threshold), accum_proof_hash="placeholder", merkle_roots={}, round_proof_stmt_hash="placeholder", coinbase_splits={p.address: "1" for p in winning_proofs})
                    gossip_msg = {"type": "new_block", "block": new_block.to_dict()}
                    threading.Thread(target=self.gossip, args=(gossip_msg,)).start()
                
                self.sent_ready_signal.add(height)
                return

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
            log_msg("DEBUG", "USER_NODE", self.owner.owner_id, f"收到来自 {data.get('bidder_id')} 对 {request_id} 的竞标")
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
        log_msg("INFO", "USER_NODE", self.owner.owner_id, f"为 {request_id} 收集到 {len(collected_bids)} 个竞标。")

        if len(collected_bids) >= num_nodes_required:
            winners = random.sample(collected_bids, num_nodes_required)
            winning_addrs = [tuple(w['bidder_addr']) for w in winners]
            winning_ids = [w['bidder_id'] for w in winners]
            log_msg("SUCCESS", "USER_NODE", self.owner.owner_id, f"文件 {self.owner.file_id} 的存储竞标完成。中标节点: {winning_ids}")

            for chunk in chunks:
                for addr in winning_addrs:
                    _send_json_line(addr, {"cmd": "chunk_distribute", "data": {"chunk": chunk.to_dict()}})

            for addr in winning_addrs:
                _send_json_line(addr, {"cmd": "finalize_storage", "data": {"file_id": self.owner.file_id}})
        else:
            log_msg("WARN", "USER_NODE", self.owner.owner_id, f"文件 {self.owner.file_id} 的存储请求失败。竞标数量不足 ({len(collected_bids)}/{num_nodes_required})。")

        if request_id in self.bids:
            del self.bids[request_id]
        self.active_requests.remove(request_id)

def run_p2p_simulation(config: P2PSimConfig):
    """运行BPoSt P2P网络的全功能模拟。"""
    log_msg("INFO", "SIMULATOR", "MAIN", f"正在使用配置启动模拟: {config}")

    # 使用Manager来创建可在进程间共享的字典和事件
    manager = multiprocessing.Manager()
    report_queue = manager.Queue()
    final_chain_reports = manager.dict()
    
    stop_events = []
    all_procs = []
    
    bootstrap_addr = ("localhost", config.base_port)
    current_port = config.base_port

    # 创建P2P（存储）节点
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

    # 创建用户节点
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

    # 启动所有进程
    for proc in all_procs:
        proc.start()
        time.sleep(0.05)

    log_msg("INFO", "SIMULATOR", "MAIN", f"已启动 {len(p2p_nodes)} 个存储节点和 {len(user_nodes)} 个用户节点。")
    log_msg("INFO", "SIMULATOR", "MAIN", f"共识和存储模拟将运行 {config.sim_duration_sec} 秒...")
    
    # --- 状态报告线程 ---
    def status_reporter(queue, stop_event, final_reports):
        latest_statuses = {}
        sim_start_time = time.time()

        while not stop_event.is_set() or not queue.empty():
            try:
                msg = queue.get(timeout=0.5)
                if msg.get("type") == "status_update":
                    latest_statuses[msg["node_id"]] = msg
                elif msg.get("type") == "final_state":
                    final_reports[msg["node_id"]] = msg["chain"]
            except Empty:
                if stop_event.is_set():
                    break
            
            # 清屏并打印状态表
            # print("[H[J", end="")
            elapsed_time = time.time() - sim_start_time
            log_msg("INFO", "SIMULATOR", "STATUS", f"--- 实时挖矿和区块链状态 (已运行: {elapsed_time:.0f}s / {config.sim_duration_sec}s) ---")
            print(f"{'Node ID':<8} | {'Height':<7} | {'Head':<10} | {'Peers':<6} | {'Mempool':<8} | {'ProofPool':<10} | {'Mining'}")
            print("-" * 85)
            
            sorted_node_ids = sorted(latest_statuses.keys())
            for node_id in sorted_node_ids:
                status = latest_statuses.get(node_id, {})
                print(f"{status.get('node_id', ''):<8} | {status.get('chain_height', ''):<7} | {status.get('chain_head', ''):<10} | {status.get('peers', ''):<6} | {status.get('mempool_size', ''):<8} | {status.get('proof_pool_size', ''):<10} | {'Active' if status.get('is_mining') else 'Idle'}")
            
            time.sleep(1) # 刷新率

    reporter_stop_event = threading.Event()
    reporter_thread = threading.Thread(target=status_reporter, args=(report_queue, reporter_stop_event, final_chain_reports))
    reporter_thread.start()

    try:
        reporter_thread.join(config.sim_duration_sec)
    except KeyboardInterrupt:
        log_msg("INFO", "SIMULATOR", "MAIN", "检测到手动中断。正在停止...")

    log_msg("INFO", "SIMULATOR", "MAIN", "模拟时间结束。正在停止节点并分析结果...")
    reporter_stop_event.set()
    for event in stop_events:
        event.set()
    
    reporter_thread.join(timeout=5)
    for proc in all_procs:
        proc.join(timeout=5)

    log_msg("INFO", "SIMULATOR", "ANALYSIS", "---------- 最终链状态 ----------")
    all_chains = dict(final_chain_reports)

    if not all_chains:
        log_msg("WARN", "SIMULATOR", "ANALYSIS", "没有从任何节点收到最终链状态。")
        return

    if not p2p_nodes:
        log_msg("WARN", "SIMULATOR", "ANALYSIS", "没有P2P节点，无法执行共识分析。")
        return

    try:
        reference_chain = max(all_chains.values(), key=len)
        log_msg("INFO", "SIMULATOR", "ANALYSIS", f"最长链高度: {len(reference_chain)}")
        log_msg("INFO", "SIMULATOR", "ANALYSIS", f"参考链哈希: {' -> '.join(reference_chain)}")

        consensus_count = sum(1 for chain in all_chains.values() if chain == reference_chain)
        consensus_rate = consensus_count / len(p2p_nodes) if p2p_nodes else 0
        log_level = "SUCCESS" if consensus_rate > 0.9 else "ERROR"
        log_msg(log_level, "SIMULATOR", "ANALYSIS", f"共识检查完成: {consensus_count} / {len(p2p_nodes)} ({consensus_rate:.0%}) 个节点达成共识。")
    except ValueError:
        log_msg("WARN", "SIMULATOR", "ANALYSIS", "链数据为空，无法分析共识。")


    log_msg("INFO", "SIMULATOR", "MAIN", "模拟结束。")
