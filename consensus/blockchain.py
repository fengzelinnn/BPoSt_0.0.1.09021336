from dataclasses import dataclass
from typing import List, Optional

from common.datastructures import Block
from utils import h_join

@dataclass
class FoldingProof:
    """折叠证明，用于累积哈希。"""
    acc_hash: str

    def __init__(self, acc_hash: Optional[str] = None):
        # 初始化累积哈希，如果未提供则使用创世哈希
        self.acc_hash = acc_hash or h_join("init_acc")

    def fold_with(self, other: 'FoldingProof') -> 'FoldingProof':
        # 将当前证明与另一个证明折叠
        return FoldingProof(h_join("fold", self.acc_hash, other.acc_hash))

class Blockchain:
    """区块链实现。"""
    def __init__(self):
        self.blocks: List[Block] = []
        self.acc: FoldingProof = FoldingProof()

    def height(self) -> int:
        # 返回区块链的当前高度
        return len(self.blocks)

    def last_hash(self) -> str:
        # 返回最后一个区块的哈希，如果链为空则返回创世哈希
        return self.blocks[-1].header_hash() if self.blocks else h_join("genesis")

    def add_block(self, block: Block, folded_round_proof: Optional[FoldingProof] = None):
        # 添加一个新区块到区块链
        if folded_round_proof:
            self.acc = self.acc.fold_with(folded_round_proof)
        self.blocks.append(block)
