import json
import socket
import multiprocessing
import threading
import time
import random
from collections import deque, defaultdict
from dataclasses import asdict
from typing import Dict, List, Tuple, Optional, Any, Set

from Crypto.dpdp import dPDP
from consensus.blockchain import Blockchain
from common.datastructures import Block, BlockBody, FileChunk, BobtailProof, DPDPProof, DPDPParams
from roles.prover import Prover
from roles.miner import Miner
from storage.manager import StorageManager
from utils import log_msg, build_merkle_tree
from crypto import deserialize_g2, g1_generator as G1, g2_generator as G2

def _json_sanitize(obj):
    if obj is None or isinstance(obj, (int, float, str, bool)):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if hasattr(obj, 'to_dict'):
        d = obj.to_dict()
        return _json_sanitize(d)
    if isinstance(obj, dict):
        return {str(_json_sanitize(k)): _json_sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_json_sanitize(v) for v in obj]
    return str(obj)

def _send_json_line(addr, payload: dict) -> Optional[dict]:
    try:
        with socket.create_connection(addr, timeout=1.5) as s:
            safe_payload = _json_sanitize(payload)
            s.sendall((json.dumps(safe_payload) + "\n").encode("utf-8"))
            data = s.recv(16384).decode("utf-8").strip()
            return json.loads(data) if data else None
    except Exception:
        return None

class Node(multiprocessing.Process):
    def __init__(self, node_id: str, host: str, port: int, bootstrap_addr: Optional[Tuple[str, int]],
                 chunk_size: int, max_storage: int, bobtail_k: int,
                 stop_event: multiprocessing.Event, report_queue: multiprocessing.Queue):
        super().__init__(daemon=True)
        self.node_id = node_id
        self.host = host
        self.port = port
        self.addr = (host, port)
        self.bootstrap_addr = bootstrap_addr
        self.report_queue = report_queue

        self.storage_manager = StorageManager(node_id, chunk_size, max_storage)
        self.prover = Prover(node_id)
        self.miner = Miner(node_id, f"addr:{node_id}")

        self.peers: Dict[str, Tuple[str, int]] = {}
        self.mempool: deque[Dict[str, Any]] = deque(maxlen=100)
        self.proof_pool: Dict[int, Dict[str, BobtailProof]] = defaultdict(dict)
        self.seen_gossip_ids: Set[str] = set()
        self.chain = Blockchain()

        self.bobtail_k = bobtail_k
        self.prepare_margin = 0
        self.difficulty_threshold = int("f" * 64, 16)
        
        self.preprepare_signals: Dict[int, Dict[str, Tuple[str, ...]]] = defaultdict(dict)
        self.sent_preprepare_signal_at: Dict[int, Tuple[str, ...]] = {}
        self.election_concluded_for: Set[int] = set()
        self.accepting_new_storage: bool = True

        # 收集每个高度的tst更新与挑战集合：{height: {node_id: {"file_roots": {...}, "challenges": {file_id: [(i,v), ...]}}}}
        self.round_tst_updates: Dict[int, Dict[str, Dict[str, Any]]] = defaultdict(dict)

        self._stop_event = stop_event
        self._server_socket: Optional[socket.socket] = None

    def run(self):
        if not self._start_server(): return
        self._discover_peers()
        log_msg("DEBUG", "NODE", self.node_id, f"进入主循环... (存储容量: {self.storage_manager.max_storage // 1024} KB)")
        last_report_time = time.time()
        last_consensus_attempt = time.time()
        while not self._stop_event.is_set():
            try:
                if self.mempool:
                    self._process_mempool()
                now = time.time()
                if now - last_consensus_attempt > random.uniform(1, 2):
                    self._attempt_consensus()
                    last_consensus_attempt = now
                if now - last_report_time > 3.0:
                    self._report_status()
                    last_report_time = now
                if not self.mempool:
                    time.sleep(1)
            except Exception as e:
                log_msg("ERROR", "NODE", self.node_id, f"主循环错误: {e}")
        final_state = {"type": "final_state", "node_id": self.node_id, "chain": [b.header_hash() for b in self.chain.blocks]}
        self.report_queue.put(final_state)
        log_msg("DEBUG", "NODE", self.node_id, "进程已停止并报告了最终状态。")

    def _report_status(self):
        height = self.chain.height()
        status = {
            "type": "status_update",
            "node_id": self.node_id,
            "chain_height": height,
            "chain_head": self.chain.last_hash(),
            "peers": len(self.peers),
            "mempool_size": len(self.mempool),
            "proof_pool_size": len(self.proof_pool.get(height + 1, {})),
            "is_mining": self.storage_manager.get_num_files() > 0,
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
            log_msg("INFO", "P2P_NET", self.node_id, f"在 {self.host}:{self.port} 上监听")
            return True
        except Exception as e:
            log_msg("CRITICAL", "P2P_NET", self.node_id, f"启动服务器失败: {e}")
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
                safe_res = _json_sanitize(response)
                conn.sendall((json.dumps(safe_res) + "\n").encode("utf-8"))
            except (json.JSONDecodeError, IOError): pass

    def _dispatch_command(self, cmd: str, data: dict) -> dict:
        handlers = {
            "get_peers": self._handle_get_peers,
            "announce": self._handle_announce,
            "gossip": self._handle_gossip,
            "inject_gossip": self._handle_inject_gossip,
            "chunk_distribute": self._handle_chunk_distribute,
            "finalize_storage": self._handle_finalize_storage,
            "dpdp_challenge": self._handle_dpdp_challenge,
        }
        handler = handlers.get(cmd)
        return handler(data) if handler else {"ok": False, "error": "未知命令"}

    def _handle_get_peers(self, data: dict) -> dict:
        return {"ok": True, "peers": self.peers}

    def _handle_announce(self, data: dict) -> dict:
        node_id, host, port = data.get("node_id"), data.get("host"), data.get("port")
        if node_id and host and port and node_id != self.node_id:
            self.peers[node_id] = (host, int(port))
        return {"ok": True}

    def _handle_gossip(self, data: dict) -> dict:
        gossip_id = data.get("gossip_id")
        if not gossip_id or gossip_id in self.seen_gossip_ids:
            return {"ok": True, "status": "已接收"}
        self.seen_gossip_ids.add(gossip_id)
        if data.get("type") == "storage_offer":
            self._handle_storage_offer(data)
        elif data.get("type") in ["bobtail_proof", "preprepare_sync", "new_block"]:
            self.mempool.append(data)
        elif data.get("type") == "tst_update":
            height = data.get("height")
            node_id = data.get("node_id")
            file_roots = data.get("file_roots", {})
            challenges = data.get("challenges", {})
            dpdp_proofs = data.get("dpdp_proofs", {})
            if height is not None and node_id:
                self.round_tst_updates[height][node_id] = {
                    "file_roots": file_roots,
                    "challenges": challenges,
                    "dpdp_proofs": dpdp_proofs,
                }
        self.gossip(data, originator=False)
        return {"ok": True, "status": "已接受"}

    def _handle_inject_gossip(self, data: dict) -> dict:
        self.gossip(data, originator=True)
        return {"ok": True, "status": "Gossip已发起"}

    def _handle_storage_offer(self, offer_data: dict):
        if self.storage_manager.can_store(offer_data.get("total_size", 0)):
            bid_msg = {
                "cmd": "storage_bid",
                "data": {
                    "type": "storage_bid",
                    "request_id": offer_data.get("request_id"),
                    "bidder_id": self.node_id,
                    "bidder_addr": self.addr,
                }
            }
            _send_json_line(tuple(offer_data.get("reply_addr")), bid_msg)

    def _handle_chunk_distribute(self, data: dict) -> dict:
        chunk = FileChunk.from_dict(data.get("chunk"))
        ok = self.storage_manager.receive_chunk(chunk)
        # 可选存入所有者的 pk_beta（G2 压缩十六进制）
        owner_pk_beta_hex = data.get("owner_pk_beta")
        if owner_pk_beta_hex:
            try:
                self.storage_manager.set_file_pk_beta(chunk.file_id, owner_pk_beta_hex)
            except Exception as _:
                pass
        return {"ok": ok}

    def _handle_finalize_storage(self, data: dict) -> dict:
        self.storage_manager.finalize_commitments()
        return {"ok": True}

    def _handle_dpdp_challenge(self, data: dict) -> dict:
        file_id = data.get("file_id")
        indices = data.get("indices")
        round_salt = str(time.time_ns())
        if not file_id or not indices:
            return {"ok": False, "error": "缺少参数"}
        try:
            # 使用当前链头（若不存在则构造简化上下文）作为挑战上下文
            last_block = self.chain.blocks[-1] if self.chain.blocks else None
            if last_block is None:
                prev_hash = self.chain.last_hash()
                timestamp = int(time.time())
                block_ctx = type("BlockLike", (), {"prev_hash": prev_hash, "timestamp": timestamp})()
            else:
                block_ctx = last_block

            chunks, tags = self.storage_manager.get_file_data_for_proof(file_id)
            proof, challenge, contributions = self.prover.prove(file_id, indices, chunks, tags, block_ctx)
            # 使用未聚合贡献更新时间状态
            self.storage_manager.update_state_after_contributions(file_id, contributions, round_salt)
            log_msg("INFO", "dPDP_PROVE", self.node_id, f"为文件 {file_id} 生成了dPDP证明。")
            return {"ok": True, "proof": asdict(proof), "challenge": challenge}
        except Exception as e:
            log_msg("ERROR", "dPDP_PROVE", self.node_id, f"为文件 {file_id} 生成证明时出错: {e}")
            return {"ok": False, "error": str(e)}

    def _discover_peers(self):
        if not self.bootstrap_addr:
            log_msg("DEBUG", "P2P_DISCOVERY", self.node_id, "作为引导节点运行。")
            return
        log_msg("DEBUG", "P2P_DISCOVERY", self.node_id, f"联系引导节点 {self.bootstrap_addr}...")
        _send_json_line(self.bootstrap_addr, {"cmd": "announce", "data": {"node_id": self.node_id, "host": self.host, "port": self.port}})
        resp = _send_json_line(self.bootstrap_addr, {"cmd": "get_peers", "data": {}})
        if resp and resp.get("ok"):
            self.peers.update({nid: tuple(addr) for nid, addr in resp.get("peers", {}).items()})
            log_msg("INFO", "P2P_DISCOVERY", self.node_id, f"发现了 {len(self.peers)} 个初始对等节点。")

    def gossip(self, message_data: dict, originator: bool = True):
        if originator:
            message_data["gossip_id"] = f"{self.node_id}:{time.time_ns()}"
            self.seen_gossip_ids.add(message_data["gossip_id"])
        if not self.peers: return
        for addr in self.peers.values():
            if addr == self.addr: continue
            _send_json_line(addr, {"cmd": "gossip", "data": message_data})

    def _process_mempool(self):
        next_height = self.chain.height() + 1
        block_msg = next((msg for msg in self.mempool if msg.get("type") == "new_block" and msg.get("height") == next_height), None)
        if block_msg:
            self.mempool.remove(block_msg)
            new_block = Block.from_dict(block_msg.get("block"))
            if new_block.prev_hash == self.chain.last_hash():
                self.chain.add_block(new_block)
                log_msg("INFO", "BLOCKCHAIN", self.node_id, f"接受了来自 {new_block.leader_id} 的区块 {new_block.height}")
                # 接受新区块后：自动发起本轮dPDP挑战并更新状态树
                try:
                    self._perform_dpdp_round(new_block)
                except Exception as e:
                    log_msg("ERROR", "dPDP_ROUND", self.node_id, f"自动挑战过程出错: {e}")
                for d in [self.proof_pool, self.preprepare_signals, self.sent_preprepare_signal_at]:
                    if next_height in d: del d[next_height]
                self.election_concluded_for.add(next_height)
            return
        try:
            msg = self.mempool.popleft()
        except IndexError:
            return
        msg_type = msg.get("type")
        height = msg.get("height")
        if height is None or height < self.chain.height() + 1 or height in self.election_concluded_for:
            return
        if msg_type == "bobtail_proof":
            proof = BobtailProof(**msg.get("proof"))
            if proof.node_id not in self.proof_pool[height]:
                self.proof_pool[height][proof.node_id] = proof
        elif msg_type == "preprepare_sync":
            received_signals = msg.get("signals", {})
            current_signals_for_height = self.preprepare_signals[height]
            updated = False
            for sender_id, proof_hashes_list in received_signals.items():
                proof_hashes_tuple = tuple(proof_hashes_list)
                if sender_id not in current_signals_for_height:
                    current_signals_for_height[sender_id] = proof_hashes_tuple
                    updated = True
            if updated:
                log_msg("DEBUG", "CONSENSUS", self.node_id, f"高度 {height} 的信号池已更新，现在有 {len(current_signals_for_height)} 个信号。")

    def _attempt_consensus(self):
        if self.storage_manager.get_num_files() == 0: return
        height = self.chain.height() + 1
        if height in self.election_concluded_for: return
        if self.node_id not in self.proof_pool.get(height, {}):
            seed = self.chain.last_hash()
            proofs = self.miner.mine(
                seed=seed,
                storage_root=self.storage_manager.get_storage_root(),
                file_roots=self.storage_manager.get_file_roots(),
                num_files=self.storage_manager.get_num_files(),
                max_nonce=10000
            )
            if proofs:
                my_proof = proofs[0]
                if self.node_id not in self.proof_pool.get(height, {}):
                    self.proof_pool[height][self.node_id] = my_proof
                    log_msg("DEBUG", "CONSENSUS", self.node_id, f"为高度 {height} 挖出了一个证明")
                    gossip_msg = {"type": "bobtail_proof", "height": height, "proof": my_proof.to_dict()}
                    self.gossip(gossip_msg)
        self._try_elect_leader(height)

    def _try_elect_leader(self, height: int):
        if height in self.election_concluded_for: return
        if height not in self.sent_preprepare_signal_at:
            candidate_proofs = list(self.proof_pool.get(height, {}).values())
            if len(candidate_proofs) >= self.bobtail_k + self.prepare_margin:
                candidate_proofs.sort(key=lambda p: p.proof_hash)
                selected_proofs = candidate_proofs[:self.bobtail_k]
                avg_hash_val = sum(int(p.proof_hash, 16) for p in selected_proofs) // self.bobtail_k
                if avg_hash_val <= self.difficulty_threshold:
                    my_proof_set = tuple(sorted([p.proof_hash for p in selected_proofs]))
                    self.sent_preprepare_signal_at[height] = my_proof_set
                    self.preprepare_signals[height][self.node_id] = my_proof_set
                    log_msg("INFO", "CONSENSUS", self.node_id, f"为高度 {height} 达成预备条件，创建自己的提案。")
        current_signals_for_height = self.preprepare_signals.get(height, {})
        if current_signals_for_height:
            sync_gossip_msg = {"type": "preprepare_sync", "height": height, "sender_id": self.node_id, "signals": current_signals_for_height}
            self.gossip(sync_gossip_msg)
        votes = defaultdict(list)
        for sender_id, proof_hashes_tuple in current_signals_for_height.items():
            votes[proof_hashes_tuple].append(sender_id)
        for proof_hashes_tuple, voters in votes.items():
            if len(voters) >= self.bobtail_k:
                log_msg("INFO", "CONSENSUS", self.node_id, f"高度 {height} 的共识达成 (提案有 {len(voters)} 票)，开始选举领导者。")
                all_known_proof_hashes = {p.proof_hash for p in self.proof_pool.get(height, {}).values()}
                if not set(proof_hashes_tuple).issubset(all_known_proof_hashes):
                    log_msg("WARN", "CONSENSUS", self.node_id, f"缺少获胜集合中的证明，等待同步...")
                    continue
                winning_proofs = [p for p in self.proof_pool.get(height, {}).values() if p.proof_hash in proof_hashes_tuple]
                if len(winning_proofs) < self.bobtail_k: continue
                winning_proofs.sort(key=lambda p: p.proof_hash)
                leader_id = winning_proofs[0].node_id
                if self.node_id == leader_id:
                    log_msg("SUCCESS", "CONSENSUS", self.node_id, f"被选举为高度 {height} 的领导者！正在创建区块...")
                    proof_hashes = [p.proof_hash for p in winning_proofs]
                    proofs_merkle_root, proofs_merkle_tree = build_merkle_tree(proof_hashes)

                    # 收集上一高度的tst更新与挑战，限于优胜者集合
                    prev_height = height - 1
                    updates_for_prev = self.round_tst_updates.get(prev_height, {})
                    winners_ids = [p.node_id for p in winning_proofs]
                    winners_roots = {nid: updates_for_prev.get(nid, {}).get("file_roots", {}) for nid in winners_ids}
                    dpdp_chals_for_winners = {nid: updates_for_prev.get(nid, {}).get("challenges", {}) for nid in winners_ids}
                    dpdp_proofs_for_winners = {nid: updates_for_prev.get(nid, {}).get("dpdp_proofs", {}) for nid in winners_ids}

                    # 新规则：在组装区块前验证每个胜者节点就其每个文件提交的 dPDP 证明
                    for nid in winners_ids:
                        file_roots = winners_roots.get(nid, {}) or {}
                        proofs_map = dpdp_proofs_for_winners.get(nid, {}) or {}
                        for fid in file_roots.keys():
                            pkg = proofs_map.get(fid)
                            if not pkg:
                                log_msg("ERROR", "CONSENSUS", self.node_id, f"缺少节点 {nid} 文件 {fid} 的 dPDP 证明包，放弃本次出块。")
                                return
                            try:
                                proof = DPDPProof(**pkg.get("proof", {}))
                                challenge = [tuple(c) for c in pkg.get("challenge", [])]
                                pk_hex = pkg.get("pk_beta", "")
                                if not pk_hex:
                                    log_msg("ERROR", "CONSENSUS", self.node_id, f"节点 {nid} 文件 {fid} 缺少 pk_beta，放弃本次出块。")
                                    return
                                pk_point = deserialize_g2(bytes.fromhex(pk_hex))
                                params = DPDPParams(g=G2, u=G1, pk_beta=pk_point, sk_alpha=0)
                                if not dPDP.check_proof(params, proof, challenge):
                                    log_msg("CRITICAL", "CONSENSUS", self.node_id, f"dPDP 证明验证失败：节点 {nid} 文件 {fid}，放弃本次出块。")
                                    return
                                else: log_msg("DEBUG", "CONSENSUS", self.node_id, f"dPDP 证明验证成功：节点 {nid} 文件 {fid}。")
                            except Exception as e:
                                log_msg("ERROR", "CONSENSUS", self.node_id, f"dPDP 验证异常：节点 {nid} 文件 {fid}，错误: {e}，放弃本次出块。")
                                return

                    block_body = BlockBody(
                        selected_k_proofs=[{"node_id": p.node_id, "proof_hash": p.proof_hash} for p in winning_proofs],
                        coinbase_splits={p.address: "1" for p in winning_proofs},
                        proofs_merkle_tree=proofs_merkle_tree,
                        dpdp_challenges=dpdp_chals_for_winners,
                    )

                    new_block = Block(
                        height=height,
                        prev_hash=self.chain.last_hash(),
                        seed=self.chain.last_hash(),
                        leader_id=leader_id,
                        body=block_body,
                        time_tree_roots=winners_roots,
                        bobtail_k=self.bobtail_k,
                        bobtail_target=hex(self.difficulty_threshold),
                        accum_proof_hash="placeholder",
                        merkle_roots={"proofs_merkle_root": proofs_merkle_root},
                        round_proof_stmt_hash="placeholder",
                        timestamp=time.time_ns(),
                    )
                    gossip_msg = {"type": "new_block", "height": height, "block": new_block.to_dict()}
                    self.gossip(gossip_msg)
                self.election_concluded_for.add(height)
                return

    def _perform_dpdp_round(self, accepted_block: Block):
        """
        在接受新区块后，基于该区块上下文对本节点存储的每个文件发起公开挑战并更新状态树，
        然后广播本轮的文件状态树根与挑战集合。
        """
        if self.storage_manager.get_num_files() == 0:
            return
        round_salt = str(time.time_ns())
        challenges_by_file: Dict[str, List[Tuple[int, int]]] = {}
        for fid in self.storage_manager.list_file_ids():
            chunks, tags = self.storage_manager.get_file_data_for_proof(fid)
            proof, challenge, contributions = self.prover.prove(fid, [], chunks, tags, accepted_block)
            # 使用未聚合贡献更新状态树
            self.storage_manager.update_state_after_contributions(fid, contributions, round_salt)
            challenges_by_file[fid] = challenge
        # 广播本轮的状态树根与挑战集合
        roots = self.storage_manager.get_file_roots()

        # 组装每个文件的 dPDP 证明包：proof、challenge、pk_beta
        dpdp_proofs_by_file: Dict[str, Dict] = {}
        for fid in self.storage_manager.list_file_ids():
            pk_hex = self.storage_manager.get_file_pk_beta(fid) or ""
            # 这里复用上面生成的 proof/challenge；若未在循环中缓存，则重新计算
            chunks, tags = self.storage_manager.get_file_data_for_proof(fid)
            proof, challenge, _ = self.prover.prove(fid, [], chunks, tags, accepted_block)
            dpdp_proofs_by_file[fid] = {
                "proof": proof.to_dict(),
                "challenge": challenge,
                "pk_beta": pk_hex,
            }

        msg = {
            "type": "tst_update",
            "height": accepted_block.height,
            "node_id": self.node_id,
            "file_roots": roots,
            "challenges": challenges_by_file,
            "dpdp_proofs": dpdp_proofs_by_file,
        }
        self.gossip(msg, originator=True)
        # 自身也缓存
        self.round_tst_updates[accepted_block.height][self.node_id] = {
            "file_roots": roots,
            "challenges": challenges_by_file,
            "dpdp_proofs": dpdp_proofs_by_file,
        }
