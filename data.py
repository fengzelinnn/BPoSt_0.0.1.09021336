"""
数据结构与服务器端存储状态

- FileChunk：客户端预处理后的分片（包含索引、数据、dPDP 标签、文件ID）。
- ServerStorage：服务器侧的状态容器，维护每个文件的时间状态树与面向文件集合的存储状态树。
"""
from dataclasses import dataclass, field
from typing import Dict, Optional, List

from trees import TimeStateTree, StorageStateTree
from utils import h_join


@dataclass
class FileChunk:
    """文件分片：携带 dPDP 标签以便服务器端进行承诺与证明。"""
    index: int
    data: bytes
    tag: str  # dPDP tag (client-generated)
    file_id: str = "default"


@dataclass
class ServerStorage:
    """服务器端存储视图：聚合各文件的时间状态树并形成存储状态树。"""
    # 每个文件的时间状态树
    time_trees: Dict[str, TimeStateTree] = field(default_factory=dict)  # file_id -> TimeStateTree
    # 所有时间根之上的存储状态树
    storage_tree: Optional[StorageStateTree] = None

    def add_chunk_commitment(self, file_id: str, index: int, commitment: str):
        """将某文件某索引的承诺写入对应的时间状态树（若不存在则创建）。"""
        tst = self.time_trees.get(file_id)
        if tst is None:
            tst = TimeStateTree()
            self.time_trees[file_id] = tst
        tst.leaves[index] = commitment

    def build_state(self):
        """重建所有时间状态树与存储状态树。"""
        # 重建时间状态树
        for tst in self.time_trees.values():
            tst.build()
        # 由时间根构建存储状态树
        self.storage_tree = StorageStateTree()
        for fid, tst in self.time_trees.items():
            self.storage_tree.file_roots[fid] = tst.root()
        self.storage_tree.build()

    def storage_root(self) -> str:
        """返回当前存储状态树根；若尚未构建，返回占位哈希。"""
        if self.storage_tree is None:
            return h_join("empty")
        return self.storage_tree.root()

    def export_time_roots(self) -> Dict[str, str]:
        """导出所有文件的时间状态树根（file_id -> root）。"""
        return {fid: tst.root() for fid, tst in self.time_trees.items()}

    def export_time_leaves(self, file_id: str) -> List[str]:
        """导出指定文件的时间状态树叶子序列（若未构建则为空）。"""
        tst = self.time_trees.get(file_id)
        if tst is None or tst.merkle is None:
            return []
        return tst.export_leaves()

    def num_files(self) -> int:
        """返回当前节点存储的文件数量。"""
        return len(self.time_trees)
