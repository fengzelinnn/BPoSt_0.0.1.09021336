from dataclasses import dataclass, field
from typing import Dict, Optional

from merkle import MerkleTree
from utils import h_join

@dataclass
class TimeStateTree:
    """表示单个文件状态随时间变化的默克尔树。"""
    leaves: Dict[int, str] = field(default_factory=dict)
    merkle: Optional[MerkleTree] = None

    def build(self):
        max_index = max(self.leaves.keys()) if self.leaves else -1
        seq = [self.leaves.get(i, h_join("missing", str(i))) for i in range(max_index + 1)]
        self.merkle = MerkleTree(seq)

    def root(self) -> str:
        return self.merkle.root() if self.merkle else h_join("empty")

@dataclass
class StorageStateTree:
    """聚合单个节点所有TimeStateTree根的默克尔树。"""
    file_roots: Dict[str, str] = field(default_factory=dict)
    merkle: Optional[MerkleTree] = None

    def build(self):
        leaves = [self.file_roots[fid] for fid in sorted(self.file_roots.keys())]
        self.merkle = MerkleTree(leaves)

    def root(self) -> str:
        return self.merkle.root() if self.merkle else h_join("empty")

@dataclass
class ServerStorage:
    """服务器节点整个存储状态的容器。"""
    time_trees: Dict[str, TimeStateTree] = field(default_factory=dict)
    storage_tree: Optional[StorageStateTree] = None

    def add_chunk_commitment(self, file_id: str, index: int, commitment: str):
        self.time_trees.setdefault(file_id, TimeStateTree()).leaves[index] = commitment

    def build_state(self):
        for tst in self.time_trees.values():
            tst.build()
        self.storage_tree = StorageStateTree({fid: tst.root() for fid, tst in self.time_trees.items()})
        self.storage_tree.build()

    def storage_root(self) -> str:
        return self.storage_tree.root() if self.storage_tree else h_join("empty")

    def num_files(self) -> int:
        return len(self.time_trees)
