"""
Merkle 树工具模块

提供：
- MerkleTree：构建Merkle树、返回根、生成并验证成员证明。

实现约定：
- 叶子为十六进制字符串；当叶子数量为奇数时，最后一个会在该层被复制配对。
- 根、证明使用 utils.h_join 进行确定性哈希拼接。
"""
from typing import List, Tuple

from utils import h_join


class MerkleTree:
    """简单Merkle树实现：支持构建、根查询、成员证明与验证。"""

    def __init__(self, leaves: List[str]):
        # leaves are hex strings
        self.leaves = leaves[:] if leaves else []
        self.levels: List[List[str]] = []
        if self.leaves:
            self._build()
        else:
            self.levels = [[]]

    def _build(self):
        """自底向上构建整棵树，遇到奇数个叶子时复制最后一个。
        复杂度：O(n)，n为叶子数。
        """
        level = [leaf for leaf in self.leaves]
        self.levels = [level]
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else level[i]
                parent = h_join("merkle", left, right)
                next_level.append(parent)
            level = next_level
            self.levels.append(level)

    def root(self) -> str:
        """返回Merkle根；若树为空，返回对"empty"的哈希作为占位。"""
        if not self.leaves:
            return h_join("empty")
        return self.levels[-1][0]

    def prove(self, index: int) -> List[Tuple[str, str]]:
        """生成成员证明路径：返回 (兄弟节点哈希, 方向) 列表，方向为 'L' 或 'R'。"""
        if not self.leaves:
            return []
        proof = []
        idx = index
        for level in self.levels[:-1]:
            sib_idx = idx ^ 1
            if sib_idx >= len(level):
                sibling = level[idx]
            else:
                sibling = level[sib_idx]
            direction = 'R' if idx % 2 == 0 else 'L'
            proof.append((sibling, direction))
            idx //= 2
        return proof

    @staticmethod
    def verify(leaf: str, index: int, proof: List[Tuple[str, str]], root: str) -> bool:
        """验证成员证明：从叶子沿路径重构根并与给定根比较。"""
        h = leaf
        idx = index
        for sibling, direction in proof:
            if direction == 'R':
                h = h_join("merkle", h, sibling)
            else:
                h = h_join("merkle", sibling, h)
            idx //= 2
        return h == root
