import json
import socket
import multiprocessing
import threading
import time
import random
from collections import defaultdict
from typing import Dict, List, Set, Optional, Tuple
from crypto import serialize_g2

from config import P2PSimConfig
from common.datastructures import DPDPProof
from Crypto.dpdp import dPDP
from roles.file_owner import FileOwner
from p2p.node import _send_json_line, _json_sanitize
from utils import log_msg

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
        self.stored_files_info: Dict[str, Dict] = {}

    def run(self):
        if not self._start_server(): return
        log_msg("INFO", "USER_NODE", self.owner.owner_id, f"用户节点已在 {self.host}:{self.port} 启动")
        while not self._stop_event.is_set():
            if not self.active_requests and random.random() < 0.3:
                self._try_store_file()
            # if self.stored_files_info and random.random() < 0.8:
            #     self._try_verify_file()
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
        return {"ok": False, "error": "未知命令"}

    def _handle_storage_bid(self, data: dict) -> dict:
        request_id = data.get("request_id")
        if request_id in self.active_requests:
            self.bids[request_id].append(data)
            return {"ok": True, "status": "竞标已接受"}
        return {"ok": False, "error": "请求不活跃"}

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

            self.stored_files_info[self.owner.file_id] = {
                "addrs": winning_addrs,
                "num_chunks": len(chunks)
            }

            # 提供所有者的 BN128 公钥 pk_beta（G2 序列化字节十六进制），供后续 dPDP 验证使用
            owner_pk_beta_hex = serialize_g2(self.owner.get_dpdp_params().pk_beta).hex()

            for chunk in chunks:
                for addr in winning_addrs:
                    _send_json_line(addr, {"cmd": "chunk_distribute", "data": {
                        "chunk": chunk.to_dict(),
                        "owner_pk_beta": owner_pk_beta_hex
                    }})

            for addr in winning_addrs:
                _send_json_line(addr, {"cmd": "finalize_storage", "data": {"file_id": self.owner.file_id}})
        else:
            log_msg("WARN", "USER_NODE", self.owner.owner_id, f"文件 {self.owner.file_id} 的存储请求失败。竞标数量不足。")

        if request_id in self.bids: del self.bids[request_id]
        self.active_requests.remove(request_id)

    def _try_verify_file(self):
        if not self.stored_files_info: return

        file_id = random.choice(list(self.stored_files_info.keys()))
        info = self.stored_files_info[file_id]
        storer_addrs = info["addrs"]
        num_chunks = info["num_chunks"]

        if not storer_addrs or num_chunks == 0: return

        # 针对特定的随机文件块发起随机挑战（单分片）
        target_addr = random.choice(storer_addrs)
        idx = random.randrange(num_chunks)
        challenge_indices = [idx]

        log_msg("INFO", "dPDP_VERIFY", self.owner.owner_id, f"随机挑战节点 {target_addr}：文件 {file_id} 的单个分片 index={idx}。")

        # 附带元信息，便于存储节点按轮次格式入库并在后续轮次上传
        challenge_payload = {
            "cmd": "dpdp_challenge",
            "data": {
                "file_id": file_id,
                "indices": challenge_indices,
                "meta": {
                    "type": "user_random_challenge",
                    "ts_ms": int(time.time() * 1000),
                    "initiator": self.addr,
                    "owner_id": self.owner.owner_id,
                    "persist": True
                }
            }
        }

        # 发送挑战并严格处理异常与错误响应
        response = _send_json_line(target_addr, challenge_payload)
        if response is None:
            msg = f"从节点 {target_addr} 无响应"
            log_msg("ERROR", "dPDP_VERIFY", self.owner.owner_id, msg)
            raise ConnectionError(msg)

        if not response.get("ok"):
            err = response.get("error", "未知错误")
            msg = f"节点 {target_addr} 返回错误: {err}"
            log_msg("ERROR", "dPDP_VERIFY", self.owner.owner_id, msg)
            raise RuntimeError(msg)

        try:
            proof_data = response.get("proof")
            challenge_data = response.get("challenge")

            if proof_data is None or challenge_data is None:
                raise ValueError("响应缺少必要字段: proof 或 challenge")

            if not isinstance(challenge_data, list):
                raise ValueError(f"challenge 类型异常: 期望 list，实际 {type(challenge_data)}")

            proof = DPDPProof(**proof_data)
            challenge: List[tuple[int, int]] = [tuple(c) for c in challenge_data]

            params = self.owner.get_dpdp_params()
            is_valid = dPDP.check_proof(params, proof, challenge)
            if is_valid:
                log_msg("SUCCESS", "dPDP_VERIFY", self.owner.owner_id, f"节点 {target_addr} 对文件 {file_id} 的 dPDP 证明验证成功。")
            else:
                msg = f"节点 {target_addr} 对文件 {file_id} 的 dPDP 证明验证失败！"
                log_msg("CRITICAL", "dPDP_VERIFY", self.owner.owner_id, msg)
                raise AssertionError(msg)
        except Exception as e:
            # 记录后继续抛出，避免异常被吞掉
            log_msg("ERROR", "dPDP_VERIFY", self.owner.owner_id, f"解析或验证来自 {target_addr} 的证明时出错: {e}")
            raise
