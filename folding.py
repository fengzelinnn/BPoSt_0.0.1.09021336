"""
折叠证明与IVC接口（原型/桩实现）

- FoldingProof：模拟 Nova 类折叠的常大小累加器，仅以哈希表示；
  提供 fold、zk_prove、zk_verify 等桩函数。
- NIFS：按指南暴露 K/P/P_zk/V_zk 接口以便调用方集成。

仅用于流程演示与可验证接口对接
"""
from typing import Optional

from utils import h_join


class FoldingProof:
    """
    Nova风格折叠累加器（桩实现）。常大小：单个哈希字符串。

    - fold(p1, p2) = H("fold" || p1 || p2)
    - zk_prove(acc) = H("zk" || acc)
    - zk_verify(acc, pi) == (pi == H("zk" || acc))
    """

    def __init__(self, acc_hash: Optional[str] = None):
        self.acc_hash = acc_hash or h_join("init_acc")

    def fold_with(self, other: 'FoldingProof') -> 'FoldingProof':
        return FoldingProof(h_join("fold", self.acc_hash, other.acc_hash))

    @staticmethod
    def from_statement(statement_hash: str) -> 'FoldingProof':
        return FoldingProof(h_join("stmt", statement_hash))

    # ZK-SNARK stub over the aggregated instance
    def zk_prove(self) -> str:
        return h_join("zk", self.acc_hash)

    @staticmethod
    def zk_verify(acc_hash: str, proof: str) -> bool:
        return proof == h_join("zk", acc_hash)


class NIFS:
    """
    接口：
      - K：初始化参数/累加器（这里返回初始 FoldingProof）
      - P：将上轮累加器与本轮语句进行折叠
      - P_zk：对最终累加器生成简洁证明（将其视为对累加器的 zk）
      - V_zk：验证该简洁证明
    """

    @staticmethod
    def K() -> FoldingProof:
        return FoldingProof()

    @staticmethod
    def P(prev: FoldingProof, statement_hash: str) -> FoldingProof:
        return prev.fold_with(FoldingProof.from_statement(statement_hash))

    @staticmethod
    def P_zk(acc: FoldingProof) -> str:
        return acc.zk_prove()

    @staticmethod
    def V_zk(acc_hash: str, pi: str) -> bool:
        return FoldingProof.zk_verify(acc_hash, pi)
