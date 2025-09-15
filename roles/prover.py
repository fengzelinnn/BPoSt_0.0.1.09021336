import random
from typing import List, Tuple, Dict

from py_ecc.bls12_381 import curve_order

from common.datastructures import DPDPTags, DPDPProof
from Crypto.dpdp import dPDP
from utils import log_msg

class Prover:
    """
    负责为存储的数据生成dPDP证明。
    """
    def __init__(self, node_id: str):
        self.node_id = node_id

    def prove(
        self,
        file_id: str,
        indices: List[int],
        file_chunks: Dict[int, bytes],
        file_tags: DPDPTags,
    ) -> Tuple[DPDPProof, List[Tuple[int, int]]]:
        """
        为指定的挑战生成dPDP聚合证明。

        :param file_id: 文件的ID。
        :param indices: 挑战中请求的分片索引。
        :param file_chunks: 文件中所有分片的原始数据。
        :param file_tags: 文件中所有分片的dPDP标签。
        :return: 一个元组，包含dPDP证明和完整的挑战（索引和系数）。
        """
        # 1. 生成完整的dPDP挑战（包括随机系数）
        challenge = [(i, random.randint(1, curve_order - 1)) for i in indices]

        # 2. 准备dPDP.GenProof所需的数据
        challenged_chunks = {i: file_chunks[i] for i, _ in challenge if i in file_chunks}

        # 3. 调用真实的dPDP证明生成
        proof = dPDP.GenProof(file_tags, challenged_chunks, challenge)
        log_msg("DEBUG", "dPDP", self.node_id, f"为文件 {file_id} 生成了dPDP证明")

        # 4. 返回证明和挑战
        return proof, challenge
