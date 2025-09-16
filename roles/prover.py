import random
from typing import List, Tuple, Dict

from py_ecc.bls12_381 import curve_order

from common.datastructures import DPDPTags, DPDPProof, Block
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
        block: Block
    ) -> Tuple[DPDPProof, List[Tuple[int, int]], List[Tuple[int, int, tuple]]]:
        """
        为指定轮次(由区块参数确定)生成dPDP聚合证明与未聚合贡献。

        :param block: 区块信息，提供(prev_hash, timestamp)以派生公开挑战
        :param file_id: 文件的ID。
        :param indices: 兼容参数（忽略），挑战由区块确定。
        :param file_chunks: 文件中所有分片的原始数据。
        :param file_tags: 文件中所有分片的dPDP标签。
        :return: (聚合证明, 挑战[(i,v_i)], 贡献[(i, mu_i, sigma_i)])
        """
        # 1. 生成公开挑战集合
        challenge = dPDP.gen_chal(block.prev_hash, block.timestamp, file_tags)

        # 2. 准备数据子集
        challenged_chunks = {i: file_chunks[i] for i, _ in challenge if i in file_chunks}

        # 3. 生成未聚合贡献
        contributions = dPDP.gen_contributions(file_tags, challenged_chunks, challenge)

        # 4. 基于挑战/标签生成聚合证明
        proof = dPDP.gen_proof(file_tags, challenged_chunks, challenge)
        log_msg("DEBUG", "dPDP", self.node_id, f"为文件 {file_id} 生成了dPDP证明与未聚合贡献")

        # 5. 返回三元组
        # 注意：sigma_i为G1点元组，已可序列化（由调用方处理）
        return proof, challenge, contributions
