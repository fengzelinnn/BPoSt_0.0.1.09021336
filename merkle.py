"""
Merkle树实现模块

该模块提供了一个简单的Merkle树实现，用于：
- 从一个叶子节点列表构建树。
- 获取Merkle根哈希。
- 为叶子节点生成成员资格证明。
- 验证一个叶子节点是否属于某个给定的Merkle根。

注意：
- 叶子节点应为十六进制字符串。
- 当一层中的节点数量为奇数时，最后一个节点将被复制以形成配对。
- 内部节点的哈希计算使用 `utils.h_join` 以确保确定性。
"""
from typing import List, Tuple

from utils import h_join


class MerkleTree:
    """一个简单的Merkle树实现。"""

    def __init__(self, leaves: List[str]):
        """
        初始化并构建Merkle树。

        :param leaves: 叶子节点列表，每个叶子都是一个十六进制哈希字符串。
        """
        self.leaves = leaves[:] if leaves else []  # 树的叶子节点
        self.levels: List[List[str]] = []  # 存储树的每一层节点
        if self.leaves:
            self._build()
        else:
            self.levels = [[]]

    def _build(self):
        """
        自底向上构建整棵树。
        如果当前层的节点数为奇数，则复制最后一个节点进行配对。
        """
        level = list(self.leaves)
        self.levels.append(level)

        # 持续构建直到只剩下一个根节点
        while len(level) > 1:
            next_level = []
            # 两两配对计算父节点
            for i in range(0, len(level), 2):
                left = level[i]
                # 如果是奇数个节点，则最后一个节点与自身配对
                right = level[i + 1] if i + 1 < len(level) else left
                parent = h_join("merkle", left, right)
                next_level.append(parent)
            level = next_level
            self.levels.append(level)

    def root(self) -> str:
        """返回Merkle根。如果树为空，则返回一个预定义的空树哈希。"""
        if not self.leaves:
            return h_join("empty")
        return self.levels[-1][0]

    def prove(self, index: int) -> List[Tuple[str, str]]:
        """
        为指定索引的叶子生成成员证明路径。

        :param index: 叶子节点的索引。
        :return: 证明路径，一个(兄弟节点哈希, 方向)的元组列表。
                 方向为 'L' 或 'R'，表示叶子在配对中的位置。
        """
        if not self.leaves or index < 0 or index >= len(self.leaves):
            return []
        
        proof = []
        idx = index
        # 从底层向上遍历，不包括根
        for level in self.levels[:-1]:
            # 计算兄弟节点的索引
            sib_idx = idx ^ 1  # 异或1可以快速找到配对的另一个
            if sib_idx >= len(level):
                # 如果兄弟节点不存在（奇数情况），则兄弟是其自身
                sibling = level[idx]
            else:
                sibling = level[sib_idx]
            
            # 确定当前节点是左边还是右边
            direction = 'R' if idx % 2 == 0 else 'L'
            proof.append((sibling, direction))
            # 移动到上一层
            idx //= 2
        return proof

    @staticmethod
    def verify(leaf: str, index: int, proof: List[Tuple[str, str]], root: str) -> bool:
        """
        验证一个叶子节点是否属于给定的Merkle根。

        :param leaf: 要验证的叶子节点的哈希。
        :param index: 叶子节点的原始索引。
        :param proof: `prove` 方法生成的证明路径。
        :param root: 声称的Merkle根哈希。
        :return: 如果验证成功，返回True，否则返回False。
        """
        # 从叶子开始，沿着证明路径向上计算哈希
        computed_hash = leaf
        for sibling, direction in proof:
            if direction == 'R':
                # 当前节点是左节点
                computed_hash = h_join("merkle", computed_hash, sibling)
            else:
                # 当前节点是右节点
                computed_hash = h_join("merkle", sibling, computed_hash)
        
        # 最终计算出的哈希应与根哈希匹配
        return computed_hash == root
