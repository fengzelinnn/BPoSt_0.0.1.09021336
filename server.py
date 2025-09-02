"""
存储节点（ServerNode）逻辑

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
        # In this prototype, the node_id also acts as the reward address
        self.reward_address = f"addr:{node_id}"

    def receive_chunk(self, chunk: FileChunk):
        if not self.opted_in:
            log_msg("INFO", "STORAGE", self.node_id, f"opted-out, ignore chunk f={chunk.file_id} idx={chunk.index}")
            return
        # Decide whether to store this chunk
        decision = random.random() <= self.store_prob
        if decision:
            # dPDP commitment per chunk (server-side)
            commitment = h_join("commit", chunk.tag, sha256_hex(chunk.data))
            self.storage.add_chunk_commitment(chunk.file_id, chunk.index, commitment)
            log_msg("INFO", "STORAGE", self.node_id,
                    f"ACCEPT file={chunk.file_id} idx={chunk.index} tag={chunk.tag[:12]}... commit={commitment[:12]}...")
        else:
            log_msg("INFO", "STORAGE", self.node_id,
                    f"REJECT file={chunk.file_id} idx={chunk.index} tag={chunk.tag[:12]}...")
        # Rebuild trees lazily when needed

    def finalize_initial_commitments(self):
        self.storage.build_state()

    def dpdp_prove(self, indices: List[int], round_salt: str, file_id: str) -> Tuple[str, Dict[int, str]]:
        """Return a per-node per-file aggregate proof hash and a map index->leaf commitment used.
        Additionally, simulate and log Time State Tree update as per guidelines.
        """
        # Build parts for deterministic aggregate proof hash of this round
        time_roots = self.storage.export_time_roots()
        storage_root = self.storage.storage_root()
        log_msg("INFO", "VERIFY", self.node_id,
                f"Begin dPDP GenProof file={file_id} indices={indices} time_root_prev={time_roots.get(file_id, h_join('empty'))[:12]}... sroot_prev={storage_root[:12]}...")
        parts = ["node", self.node_id, "salt", round_salt, "sroot", storage_root, "f", file_id,
                 time_roots.get(file_id, h_join("empty"))]
        per_index_commitments: Dict[int, str] = {}
        # Collect commits used this round (take from current leaves of the file's TimeStateTree)
        tst = self.storage.time_trees.get(file_id)
        if tst is None:
            tst_leaves: Dict[int, str] = {}
        else:
            tst_leaves = tst.leaves
        for idx in indices:
            commit = tst_leaves.get(idx, h_join("missing", str(idx)))
            per_index_commitments[idx] = commit
            parts.append(h_join("idx", str(idx), commit))
            log_msg("DEBUG", "VERIFY", self.node_id,
                    f"use leaf idx={idx} commit={commit[:12]}... in agg")
        proof_hash = h_join(*parts)
        log_msg("INFO", "VERIFY", self.node_id, f"Agg proof={proof_hash[:16]}... for file={file_id}")
        # Time State Tree update: fold this round's proof into each challenged leaf
        for idx in indices:
            prev_leaf = tst_leaves.get(idx, h_join("missing", str(idx)))
            new_leaf = h_join("tleaf", prev_leaf, proof_hash, round_salt)
            self.storage.add_chunk_commitment(file_id, idx, new_leaf)
            log_msg("DEBUG", "VERIFY", self.node_id,
                    f"update tleaf idx={idx} prev={prev_leaf[:12]}... -> new={new_leaf[:12]}...")
        # Rebuild all trees to reflect updated time and storage states
        self.storage.build_state()
        log_msg("INFO", "VERIFY", self.node_id,
                f"After update: time_root={self.storage.time_trees.get(file_id).root()[:12]}... sroot={self.storage.storage_root()[:12]}...")
        return proof_hash, per_index_commitments

    def pow_samples(self, seed: str, num_samples: int = 64, k: int = 5) -> Tuple[int, List[Tuple[int, int]]]:
        """Deprecated in favor of Bobtail; kept for backward-compat in older demos."""
        samples = []
        for nonce in range(num_samples):
            v = int(sha256_hex(f"{seed}|{self.node_id}|{nonce}".encode()), 16)
            samples.append((nonce, v))
        samples.sort(key=lambda x: x[1])
        topk = samples[:k]
        agg = sum(v for _, v in topk)
        return agg, topk

    def mine_bobtail(self, seed: str, max_nonce: int = 512) -> Dict[str, str]:
        """Mine a Bobtail proof using Storage State Tree root and a nonce.
        Returns a proof set dict with keys: node_id, address, root, nonce, proof_value.
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

    def export_merkle_leaves(self) -> List[str]:
        # For demo: export storage state tree leaves (i.e., time roots)
        if self.storage.storage_tree is None:
            return []
        return self.storage.storage_tree.export_leaves()
