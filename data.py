from dataclasses import dataclass, field
from typing import Dict, Optional, List

from trees import TimeStateTree, StorageStateTree
from utils import h_join


@dataclass
class FileChunk:
    index: int
    data: bytes
    tag: str  # dPDP tag (client-generated)
    file_id: str = "default"


@dataclass
class ServerStorage:
    # Per-file time state trees
    time_trees: Dict[str, TimeStateTree] = field(default_factory=dict)  # file_id -> TimeStateTree
    # Storage state tree over time roots
    storage_tree: Optional[StorageStateTree] = None

    def add_chunk_commitment(self, file_id: str, index: int, commitment: str):
        tst = self.time_trees.get(file_id)
        if tst is None:
            tst = TimeStateTree()
            self.time_trees[file_id] = tst
        tst.leaves[index] = commitment

    def build_state(self):
        # Build all time state trees
        for tst in self.time_trees.values():
            tst.build()
        # Build storage state tree from time roots
        self.storage_tree = StorageStateTree()
        for fid, tst in self.time_trees.items():
            self.storage_tree.file_roots[fid] = tst.root()
        self.storage_tree.build()

    def storage_root(self) -> str:
        if self.storage_tree is None:
            return h_join("empty")
        return self.storage_tree.root()

    def export_time_roots(self) -> Dict[str, str]:
        return {fid: tst.root() for fid, tst in self.time_trees.items()}

    def export_time_leaves(self, file_id: str) -> List[str]:
        tst = self.time_trees.get(file_id)
        if tst is None or tst.merkle is None:
            return []
        return tst.export_leaves()

    def num_files(self) -> int:
        return len(self.time_trees)
