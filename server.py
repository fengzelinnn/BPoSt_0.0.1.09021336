"""
存储节点

- 接收/选择性存储分片，构建时间/存储状态树；
- 生成按需 dPDP 聚合证明并更新时间状态树；
- 参与 Bobtail PoW（基于存储状态树根）并导出用于上链的叶子。
"""
import random
from typing import List, Tuple, Dict

from data import FileChunk, ServerStorage
from utils import h_join, sha256_hex, log_msg


class ServerNode:
    def __init__(self, node_id: str, store_prob: float = 0.7):
        self.node_id = node_id
        self.store_prob = store_prob
        self.storage = ServerStorage()
        self.opted_in = True
        # 在该原型中，node_id 同时充当奖励地址
        self.reward_address = f"addr:{node_id}"
        # SimPy 环境（可选绑定）
        self.env = None

    def bind_env(self, env):
        self.env = env
        return self

    def receive_chunk(self, chunk: FileChunk):
        if not self.opted_in:
            # 已选择退出；抑制逐分片日志，保持文件级视图
            return
        # 决定是否存储该分片
        decision = random.random() <= self.store_prob
        if decision:
            # 每个分片的 dPDP 承诺（服务器侧）
            commitment = h_join("commit", chunk.tag, sha256_hex(chunk.data))
            self.storage.add_chunk_commitment(chunk.file_id, chunk.index, commitment)
            # 文件级监控：不记录每个分片日志，仅在内部标记接受
            # log_msg("INFO", "STORAGE", self.node_id,
            #         f"ACCEPT file={chunk.file_id} idx={chunk.index} tag={chunk.tag[:12]}... commit={commitment[:12]}...")
        else:
            # 抑制每个分片的拒绝日志，保持简洁
            pass
        # 按需惰性重建树

    def finalize_initial_commitments(self):
        self.storage.build_state()

    def dpdp_prove(self, indices: List[int], round_salt: str, file_id: str) -> Tuple[str, Dict[int, str]]:
        """返回每个节点每个文件的聚合证明哈希值以及所使用的索引->叶子节点承诺, 模拟并记录时间状态树的更新。
        """
        # 组装本轮确定性聚合证明哈希的各组成部分
        time_roots = self.storage.export_time_roots()
        storage_root = self.storage.storage_root()
        log_msg("INFO", "VERIFY", self.node_id,
                f"GenProof file={file_id} challenged={len(indices)} seed={round_salt[:8]} prev_time_root={time_roots.get(file_id, h_join('empty'))[:12]}... prev_sroot={storage_root[:12]}...")
        parts = ["node", self.node_id, "salt", round_salt, "sroot", storage_root, "f", file_id,
                 time_roots.get(file_id, h_join("empty"))]
        per_index_commitments: Dict[int, str] = {}
        # 收集本轮使用的承诺（取自该文件时间状态树的当前叶子）
        tst = self.storage.time_trees.get(file_id)
        if tst is None:
            tst_leaves: Dict[int, str] = {}
        else:
            tst_leaves = tst.leaves
        for idx in indices:
            commit = tst_leaves.get(idx, h_join("missing", str(idx)))
            per_index_commitments[idx] = commit
            parts.append(h_join("idx", str(idx), commit))
            # 抑制逐索引叶子信息，保持文件级日志
        proof_hash = h_join(*parts)
        log_msg("INFO", "VERIFY", self.node_id, f"Agg proof={proof_hash[:16]}... for file={file_id}")
        # 时间状态树更新：将本轮证明折叠进每个被挑战的叶子
        for idx in indices:
            prev_leaf = tst_leaves.get(idx, h_join("missing", str(idx)))
            new_leaf = h_join("tleaf", prev_leaf, proof_hash, round_salt)
            self.storage.add_chunk_commitment(file_id, idx, new_leaf)
            # 抑制逐索引的 tleaf 更新日志
        # 重建所有树以反映最新的时间与存储状态
        self.storage.build_state()
        log_msg("INFO", "VERIFY", self.node_id,
                f"After update: time_root={self.storage.time_trees.get(file_id).root()[:12]}... sroot={self.storage.storage_root()[:12]}...")
        return proof_hash, per_index_commitments

    # ---- SimPy 进程封装 ----
    def dpdp_prove_proc(self, env, indices: List[int], round_salt: str, file_id: str, compute_delay: float = 0.005):
        """SimPy 进程包装：在模拟的计算延迟后调用 dpdp_prove。"""
        log_msg("DEBUG", "VERIFY", self.node_id, f"[t={env.now}] dpdp_prove_proc begin for file={file_id}")
        # 模拟计算耗时
        yield env.timeout(compute_delay)
        proof_hash, per_idx = self.dpdp_prove(indices, round_salt, file_id)
        log_msg("INFO", "VERIFY", self.node_id, f"[t={env.now}] dpdp_prove_proc end proof={proof_hash[:16]}...")
        return proof_hash, per_idx

    def pow_samples(self, seed: str, num_samples: int = 64, k: int = 5) -> Tuple[int, List[Tuple[int, int]]]:
        """已被 Bobtail 取代；为兼容早期演示保留。"""
        samples = []
        for nonce in range(num_samples):
            v = int(sha256_hex(f"{seed}|{self.node_id}|{nonce}".encode()), 16)
            samples.append((nonce, v))
        samples.sort(key=lambda x: x[1])
        topk = samples[:k]
        agg = sum(v for _, v in topk)
        return agg, topk

    def mine_bobtail(self, seed: str, max_nonce: int = 512) -> Dict[str, str]:
        """使用存储状态树根与 nonce 挖 Bobtail 证明。
        返回包含以下键的字典：node_id, address, root, nonce, proof_value。
        """
        root = self.storage.storage_root()
        best_v = None
        best_nonce = 0
        for nonce in range(max_nonce):
            h = sha256_hex(f"bobtail|{seed}|{root}|{self.node_id}|{nonce}".encode())
            v = int(h, 16)
            if best_v is None or v < best_v:
                best_v = v
                best_nonce = nonce
        return {
            "node_id": self.node_id,
            "address": self.reward_address,
            "root": root,
            "nonce": str(best_nonce),
            "proof_value": str(best_v if best_v is not None else 0),
            "lots": str(max(1, self.storage.num_files())),
        }

    def mine_bobtail_proc(self, env, seed: str, max_nonce: int = 512, compute_per_nonce: float = 0.0001):
        """SimPy 进程包装：按尝试的 nonce 数量模拟耗时，并调用 mine_bobtail。"""
        log_msg("DEBUG", "SYSTEM", self.node_id, f"[t={env.now}] mine_bobtail_proc begin max_nonce={max_nonce}")
        # 模拟与工作量成正比的耗时
        yield env.timeout(compute_per_nonce * max_nonce)
        ps = self.mine_bobtail(seed=seed, max_nonce=max_nonce)
        log_msg("INFO", "SYSTEM", self.node_id, f"[t={env.now}] mine_bobtail_proc end v={int(ps['proof_value']):x}")
        return ps

    def export_merkle_leaves(self) -> List[str]:
        # 演示用途：导出存储状态树的叶子（即各文件的时间根）
        if self.storage.storage_tree is None:
            return []
        return self.storage.storage_tree.export_leaves()
