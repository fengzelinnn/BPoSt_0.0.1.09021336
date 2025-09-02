"""
区块链与区块数据结构

- Block：单个区块的头部字段与序列化哈希（含Bobtail相关字段）。
- Blockchain：区块链容器，维护折叠证明累加器（FoldingProof）与区块列表。

设计说明：
Block.header_hash() 将所有需要共识/验证的字段以确定性顺序拼接后哈希，避免歧义。
折叠证明的累计哈希存于链级别的 acc；每次添加区块时 acc 与当轮折叠证明进行 fold，形成跨轮次的常大小累积证明。
"""
from dataclasses import dataclass
from typing import Dict, List

from folding import FoldingProof
from utils import h_join


@dataclass
class Block:
    """
    区块头数据结构：
    - 包含上一块哈希、随机种子（上一块哈希）、Leader 标识、折叠证明累计哈希预览、
      各节点存储状态树根、当轮证明语句哈希，以及 Bobtail 相关的前 k 名证明与分配信息。
    注意：header_hash() 将字段以确定顺序拼接后哈希。
    """
    height: int
    prev_hash: str
    seed: str
    leader_id: str
    accum_proof_hash: str
    merkle_roots: Dict[str, str]  # node_id -> merkle root used in proofs
    round_proof_stmt_hash: str  # statement hash for this round before folding
    # Bobtail-specific fields
    bobtail_k: int = 0
    bobtail_target: str = "0"
    selected_k_proofs: List[Dict[str, str]] = None  # list of proof sets for the k winners (ordered by proof_value asc)
    included_post_trees: Dict[str, List[str]] = None  # node_id -> merkle leaves
    coinbase_splits: Dict[str, str] = None  # node_id -> fraction string (e.g., "1/3")

    def header_hash(self) -> str:
        parts = [
            "block", str(self.height), self.prev_hash, self.seed, self.leader_id,
            self.accum_proof_hash, self.round_proof_stmt_hash,
            "bobtail", str(self.bobtail_k), self.bobtail_target
        ]
        # Include merkle roots deterministically ordered
        for nid in sorted(self.merkle_roots.keys()):
            parts.append("root")
            parts.append(nid)
            parts.append(self.merkle_roots[nid])
        # Include selected k proofs ordered by proof_value ascending deterministically
        if self.selected_k_proofs:
            for p in self.selected_k_proofs:
                parts.extend(
                    ["proof", p.get("node_id", ""), p.get("address", ""), p.get("root", ""), p.get("nonce", ""),
                     p.get("proof_value", "")])
        # Include included trees deterministically by node_id
        if self.included_post_trees:
            for nid in sorted(self.included_post_trees.keys()):
                parts.append("tree")
                parts.append(nid)
                leaves = self.included_post_trees[nid] or []
                for leaf in leaves:
                    parts.append(leaf)
        # Include coinbase splits deterministically by node_id
        if self.coinbase_splits:
            for nid in sorted(self.coinbase_splits.keys()):
                parts.extend(["split", nid, self.coinbase_splits[nid]])
        return h_join(*parts)


class Blockchain:
    """
    区块链容器：
    - blocks：区块列表
    - acc：跨轮次折叠证明累加器（常大小），用于最终一次验证
    """

    def __init__(self):
        self.blocks: List[Block] = []
        self.acc: FoldingProof = FoldingProof()  # 累计折叠证明（常大小）

    def last_hash(self) -> str:
        """返回最新区块头哈希，空链时返回创世占位哈希。"""
        if not self.blocks:
            return h_join("genesis")
        return self.blocks[-1].header_hash()

    def add_block(self, block: Block, folded_round_proof: FoldingProof):
        """将区块追加到链上，并用当轮折叠证明更新全局累加器。"""
        # 使用当轮折叠证明更新累计证明（acc）
        self.acc = self.acc.fold_with(folded_round_proof)
        # 记录区块
        self.blocks.append(block)
