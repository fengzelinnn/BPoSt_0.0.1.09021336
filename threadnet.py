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
        self.difficulty_threshold = int("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
        
        self.ready_signals: Dict[int, Dict[str, Tuple[str, ...]]] = defaultdict(dict)
        self.sent_ready_signal: Set[int] = set()

        self._stop_event = stop_event
        self._server_socket: Optional[socket.socket] = None

    def run(self):
        if not self._start_server(): return
        self._discover_peers()
        log_msg("DEBUG", "NODE", self.node.node_id, f"进入主循环... (存储容量: {self.node.max_storage // 1024} KB)")
        while not self._stop_event.is_set():
            try:
                self._process_mempool()
                self._attempt_consensus()
                time.sleep(random.uniform(0.5, 1.5))
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

    def _start_server(self) -> bool:
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(self.addr)
            self._server_socket.listen(50)
            self._server_socket.settimeout(0.5)
            # 在进程内部，监听器仍然可以使用线程，因为它们共享该进程的内存
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
            "inject_gossip": self._handle_inject_gossip, # 新增：处理来自模拟器的gossip注入
            "storage_bid": self._handle_storage_bid,
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
        # 这个方法允许模拟器（或其他外部实体）安全地发起一次gossip广播
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

    def _handle_storage_bid(self, data: dict) -> dict:
        # 将收到的竞标放入报告队列，由主模拟器进程处理
        self.report_queue.put(data)
        return {"ok": True, "status": "bid_received_by_node"}

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
        while self.mempool:
            msg = self.mempool.popleft()
            msg_type = msg.get("type")
            if msg_type == "bobtail_proof":
                proof_data, height = msg.get("proof"), msg.get("height")
                if not proof_data or height is None or height < self.chain.height() + 1: continue
                proof = BobtailProof(**proof_data)
                if proof.node_id == self.node.node_id: continue
                if proof.node_id not in self.proof_pool[height]:
                    self.proof_pool[height][proof.node_id] = proof
                    log_msg("DEBUG", "CONSENSUS", self.node.node_id, f"收到并存储了来自 {proof.node_id} 的高度 {height} 的证明")
            elif msg_type == "ready_signal":
                height, sender_id = msg.get("height"), msg.get("sender_id")
                proof_hashes = tuple(msg.get("proof_hashes", []))
                if not height or not sender_id or not proof_hashes or height < self.chain.height() + 1: continue
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

        height = self.chain.height() + 1
        seed = self.chain.last_hash()

        if self.node.node_id not in self.proof_pool[height] and height not in self.sent_ready_signal:
            proofs = self.node.mine_bobtail(seed=seed, max_nonce=10000)
            if not proofs: return
            my_proof = proofs[0]
            self.proof_pool[height][self.node.node_id] = my_proof
            log_msg("DEBUG", "CONSENSUS", self.node.node_id, f"为高度 {height} 挖出了一个证明")
            self.gossip({"type": "bobtail_proof", "height": height, "proof": my_proof.to_dict()})

        self._try_elect_leader(height)

    def _try_elect_leader(self, height: int):
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
                self.gossip({"type": "ready_signal", "height": height, "sender_id": self.node.node_id, "proof_hashes": winning_hashes})

        if not self.ready_signals.get(height): return

        votes = defaultdict(list)
        for sender_id, proof_hashes_tuple in self.ready_signals[height].items():
            votes[proof_hashes_tuple].append(sender_id)

        for proof_hashes_tuple, voters in votes.items():
            if len(voters) >= self.bobtail_k:
                all_proofs_at_height = self.proof_pool.get(height, {})
                winning_proofs = [p for p in all_proofs_at_height.values() if p.proof_hash in proof_hashes_tuple]
                if len(winning_proofs) < self.bobtail_k: return

                winning_proofs.sort(key=lambda p: p.proof_hash)
                leader_id = winning_proofs[0].node_id

                if self.node.node_id == leader_id:
                    log_msg("SUCCESS", "CONSENSUS", self.node.node_id, f"被选举为高度 {height} 的领导者！正在创建区块...")
                    time_tree_roots = {p.node_id: p.file_roots for p in winning_proofs}
                    selected_proofs_summary = [{"node_id": p.node_id, "proof_hash": p.proof_hash} for p in winning_proofs]
                    new_block = Block(height=height, prev_hash=self.chain.last_hash(), seed=self.chain.last_hash(), leader_id=leader_id, time_tree_roots=time_tree_roots, selected_k_proofs=selected_proofs_summary, bobtail_k=self.bobtail_k, bobtail_target=hex(self.difficulty_threshold), accum_proof_hash="placeholder", merkle_roots={}, round_proof_stmt_hash="placeholder", coinbase_splits={p.address: "1" for p in winning_proofs})
                    self.gossip({"type": "new_block", "block": new_block.to_dict()})
                
                self.sent_ready_signal.add(height)
                return

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

def run_p2p_simulation(config: P2PSimConfig):
    """运行BPoSt P2P网络的全功能模拟。"""
    log_msg("INFO", "SIMULATOR", "MAIN", f"正在使用配置启动模拟: {config}")

    report_queue = multiprocessing.Queue()
    stop_events = []
    nodes: List[P2PNode] = []
    node_map: Dict[str, P2PNode] = {}
    bootstrap_addr = ("localhost", config.base_port)

    for i in range(config.num_nodes):
        node_id = f"S{i}"
        port = config.base_port + i
        node_capacity = random.randint(config.min_storage_kb, config.max_storage_kb) * 1024
        storage_node = StorageNode(node_id=node_id, chunk_size=config.chunk_size, max_storage=node_capacity)
        
        stop_event = multiprocessing.Event()
        p2p_node = P2PNode(server_node=storage_node, host="localhost", port=port, 
                             bootstrap_addr=bootstrap_addr if i > 0 else None, 
                             bobtail_k=config.bobtail_k, 
                             stop_event=stop_event, report_queue=report_queue)
        nodes.append(p2p_node)
        stop_events.append(stop_event)
        node_map[node_id] = p2p_node

    for node in nodes:
        node.start()
        time.sleep(0.05)

    log_msg("INFO", "SIMULATOR", "MAIN", f"已启动 {len(nodes)} 个P2P节点进程。等待网络稳定...")
    time.sleep(5)

    file_owners = [FileOwner(f"0{i}", config.chunk_size) for i in range(config.num_file_owners)]
    for owner in file_owners:
        num_nodes_required = min(random.randint(config.min_storage_nodes, config.max_storage_nodes), config.num_nodes)

        log_msg("INFO", "SIMULATOR", "OWNER", f"用户 {owner.owner_id} 发起存储请求，需要 {num_nodes_required} 个节点")
        chunks, _ = owner.prepare_storage_request(min_size_bytes=config.min_file_kb * 1024, max_size_bytes=config.max_file_kb * 1024, num_nodes=num_nodes_required)
        total_size = len(chunks) * config.chunk_size
        request_id = f"req-{owner.file_id}"

        # 修复：通过向代理节点发送网络命令来注入gossip，而不是直接调用方法
        proxy_node = random.choice(nodes)
        log_msg("INFO", "SIMULATOR", "OWNER", f"用户 {owner.owner_id} 通过代理 {proxy_node.node.node_id} 广播对文件 {owner.file_id} ({total_size // 1024}KB) 的存储要约")
        offer_msg = {"type": "storage_offer", "request_id": request_id, "file_id": owner.file_id, "total_size": total_size, "reply_addr": proxy_node.addr}
        
        # 直接向代理节点的套接字发送命令，让它自己发起gossip
        _send_json_line(proxy_node.addr, {"cmd": "inject_gossip", "data": offer_msg})

        log_msg("INFO", "SIMULATOR", "MAIN", f"等待 {config.bid_wait_sec} 秒以收集竞标...")
        bids = []
        start_time = time.time()
        while time.time() - start_time < config.bid_wait_sec:
            try:
                # 从所有子进程共享的队列中获取竞标信息
                msg = report_queue.get(timeout=0.1)
                if msg.get("type") == "storage_bid" and msg.get("request_id") == request_id:
                    bids.append(msg)
            except Empty:
                continue
        
        log_msg("INFO", "SIMULATOR", "MAIN", f"为请求 {request_id} 收集到 {len(bids)} 个竞标。")

        if len(bids) >= num_nodes_required:
            winners = random.sample(bids, num_nodes_required)
            winning_addrs = [tuple(w['bidder_addr']) for w in winners]
            winning_ids = [w['bidder_id'] for w in winners]
            log_msg("SUCCESS", "SIMULATOR", "MAIN", f"文件 {owner.file_id} 的存储竞标完成。中标节点: {winning_ids}")

            for chunk in chunks:
                for addr in winning_addrs:
                    _send_json_line(addr, {"cmd": "chunk_distribute", "data": {"chunk": chunk.to_dict()}})
            
            for addr in winning_addrs:
                _send_json_line(addr, {"cmd": "finalize_storage", "data": {"file_id": owner.file_id}})
        else:
            log_msg("WARN", "SIMULATOR", "MAIN", f"文件 {owner.file_id} 的存储请求失败。竞标数量不足 ({len(bids)}/{num_nodes_required})。")

        time.sleep(random.uniform(0.1, 0.2))

    log_msg("INFO", "SIMULATOR", "MAIN", f"所有文件分发完成。共识模拟将运行 {config.sim_duration_sec} 秒...")
    time.sleep(config.sim_duration_sec)

    log_msg("INFO", "SIMULATOR", "MAIN", "模拟时间结束。正在停止节点并分析结果...")
    for event in stop_events:
        event.set()
    for node in nodes:
        node.join(timeout=5)

    log_msg("INFO", "SIMULATOR", "ANALYSIS", "---------- 最终链状态 ----------")
    all_chains = {}
    while not report_queue.empty():
        try:
            msg = report_queue.get_nowait()
            if msg.get("type") == "final_state":
                all_chains[msg["node_id"]] = msg["chain"]
        except Empty:
            break

    if not all_chains:
        log_msg("WARN", "SIMULATOR", "ANALYSIS", "没有从任何节点收到最终链状态。队列可能为空或消息类型不匹配。")
        return

    reference_chain = max(all_chains.values(), key=len)
    log_msg("INFO", "SIMULATOR", "ANALYSIS", f"最长链高度: {len(reference_chain)}")
    log_msg("INFO", "SIMULATOR", "ANALYSIS", f"参考链哈希: {' -> '.join(reference_chain)}")

    consensus_count = sum(1 for chain in all_chains.values() if chain == reference_chain)
    consensus_rate = consensus_count / len(nodes) if nodes else 0
    log_level = "SUCCESS" if consensus_rate > 0.9 else "ERROR"
    log_msg(log_level, "SIMULATOR", "ANALYSIS", f"共识检查完成: {consensus_count} / {len(nodes)} ({consensus_rate:.0%}) 个节点达成共识。")

    log_msg("INFO", "SIMULATOR", "MAIN", "模拟结束。")
