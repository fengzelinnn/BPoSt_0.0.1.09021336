"""
多维状态树

- TimeStateTree：针对单个文件，随轮次更新的时间状态树（叶子为分片/索引承诺）。
- StorageStateTree：针对单个节点，叶子为其所有文件的时间状态树根，用于量化存储贡献。
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from merkle import MerkleTree
from utils import h_join


@dataclass
class TimeStateTree:
    """
    单文件时间状态树：
    - 叶子：每个分片（索引）的承诺值；每轮将新证明折叠/更新到对应叶子。
    - 根：作为该文件当前轮的公开承诺，进入节点的存储状态树。
    """
    leaves: Dict[int, str] = field(default_factory=dict)  # index -> leaf value
    merkle: Optional[MerkleTree] = None

    def build(self):
        max_index = max(self.leaves.keys()) if self.leaves else -1
        seq: List[str] = []
        for i in range(max_index + 1):
            seq.append(self.leaves.get(i, h_join("missing", str(i))))
        self.merkle = MerkleTree(seq)

    def root(self) -> str:
        if self.merkle is None:
            return h_join("empty")
        return self.merkle.root()

    def update_leaf(self, idx: int, new_val: str):
        self.leaves[idx] = new_val

    def export_leaves(self) -> List[str]:
        if self.merkle is None:
            return []
        return self.merkle.leaves[:]


@dataclass
class StorageStateTree:
    """
    节点级存储状态树：
    - 叶子：该节点所存每个文件的时间状态树根（按 file_id 排序稳定化）。
    - 根：代表节点在当前轮的整体存储承诺，用于PoW(Bobtail)与上链证明。
    """
    file_roots: Dict[str, str] = field(default_factory=dict)  # file_id -> time_state_root
    merkle: Optional[MerkleTree] = None

    def build(self):
        # Deterministic order over file ids
        ids = sorted(self.file_roots.keys())
        leaves = [self.file_roots[fid] for fid in ids]
        self.merkle = MerkleTree(leaves)

    def root(self) -> str:
        if self.merkle is None:
            return h_join("empty")
        return self.merkle.root()

    def export_leaves(self) -> List[str]:
        if self.merkle is None:
            return []
        return self.merkle.leaves[:]
