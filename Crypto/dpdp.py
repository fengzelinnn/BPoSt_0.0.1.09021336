import random
from hashlib import sha256
from typing import List, Dict, Tuple

from py_ecc.optimized_bls12_381 import (
    G1, G2,
    pairing,
    add,
    multiply,
    is_inf,
    FQ,
)
from py_ecc.bls.g2_primitives import G1_to_pubkey
from py_ecc.bls12_381 import curve_order
from py_ecc.bls.hash_to_curve import hash_to_G1 as _hash_to_G1

from common.datastructures import DPDPParams, DPDPTags, DPDPProof
from utils import sha256_hex
from merkle import MerkleTree

G1_IDENTITY = G1

H1_DST = b'BPoSt-H1-DST-v1.0'

def hash_to_G1(message: bytes):
    """hash_to_G1 的封装, 提供一致的域分隔."""
    return _hash_to_G1(message, H1_DST, sha256)

def chunk_to_int(chunk: bytes) -> int:
    """
    将文件块转换为模曲线阶的整数。
    """
    h = sha256_hex(chunk)
    return int(h, 16)

class dPDP:
    """基于 BLS 签名的 dPDP 方案实现."""

    @staticmethod
    def KeyGen(security: int = 256) -> DPDPParams:
        """生成 dPDP 参数和密钥."""
        sk_alpha = random.randint(1, curve_order - 1)
        g = G2
        u = G1
        pk_beta = multiply(g, sk_alpha)
        return DPDPParams(
            g=g,
            u=u,
            pk_beta=pk_beta,
            sk_alpha=sk_alpha
        )

    @staticmethod
    def TagFile(params: DPDPParams, file_chunks: List[bytes]) -> DPDPTags:
        """为每个文件块生成 dPDP 标签."""
        tags: List[Tuple[FQ, FQ, FQ]] = []
        for i, chunk in enumerate(file_chunks):
            b_i = chunk_to_int(chunk)
            h_i = hash_to_G1(str(i).encode())
            term1 = h_i
            term2 = multiply(params.u, b_i)
            base_point = add(term1, term2)
            sigma_i = multiply(base_point, params.sk_alpha)
            tags.append(sigma_i)
        return DPDPTags(tags=tags)

    @staticmethod
    def GenProof(tags: DPDPTags, file_chunks: Dict[int, bytes], challenge: List[Tuple[int, int]]) -> DPDPProof:
        """为挑战生成 dPDP 证明."""
        agg_mu = 0
        agg_sigma = G1_IDENTITY
        for i, v_i in challenge:
            if i >= len(tags.tags):
                raise ValueError(f"索引 {i} 在提供的块/标签中未找到，无法生成证明")
            b_i = chunk_to_int(file_chunks[i])
            sigma_i = tags.tags[i]
            agg_mu = (agg_mu + v_i * b_i) % curve_order
            agg_sigma = add(agg_sigma, multiply(sigma_i, v_i))
        return DPDPProof(mu=agg_mu, sigma=agg_sigma)

    @staticmethod
    def CheckProof(params: DPDPParams, proof: DPDPProof, challenge: List[Tuple[int, int]]) -> bool:
        """验证 dPDP 证明."""
        if is_inf(proof.sigma):
            return not challenge
        lhs = pairing(params.g, proof.sigma)
        agg_h = G1_IDENTITY
        for i, v_i in challenge:
            h_i = hash_to_G1(str(i).encode())
            agg_h = add(agg_h, multiply(h_i, v_i))
        mu_u = multiply(params.u, proof.mu)
        rhs_g1_point = add(agg_h, mu_u)
        rhs = pairing(params.pk_beta, rhs_g1_point)
        return lhs == rhs

    @staticmethod
    def VerifyProofWithMerkle(
        params: DPDPParams,
        proof: DPDPProof,
        challenge: List[Tuple[int, int]],
        challenged_data: Dict[int, Tuple[bytes, List[Tuple[str, str]]]],
        merkle_root: str
    ) -> bool:
        """
        验证 dPDP 证明及被挑战数据块的 Merkle 证明。

        此函数供领导者/验证者使用，执行完整验证流程：
        1. 验证每个被挑战数据块的 Merkle 证明。
        2. 从已验证的数据块中重新计算聚合哈希 ('mu')。
        3. 检查重新计算的 'mu' 是否与 dPDP 证明中的 'mu' 匹配。
        4. 执行最终的 dPDP 密码学检查。

        :param params: dPDP 参数。
        :param proof: 来自证明者的 DPDPProof 对象。
        :param challenge: 已发出的挑战。
        :param challenged_data: 映射挑战索引到 (数据块字节, Merkle 证明路径) 的字典。
        :param merkle_root: 文件块的公共 Merkle 根。
        :return: 如果整个证明有效，则返回 True，否则返回 False。
        """
        # 步骤 1 & 2: 验证 Merkle 证明并重新计算 mu
        recomputed_mu = 0
        
        # 确保证明数据与挑战一一对应
        if {i for i, v in challenge} != set(challenged_data.keys()):
            return False

        for i, v_i in challenge:
            chunk, merkle_proof = challenged_data[i]

            # 验证数据块的 Merkle 证明
            leaf = sha256_hex(chunk)
            if not MerkleTree.verify(leaf, i, merkle_proof, merkle_root):
                return False  # Merkle 证明无效

            # Merkle 证明有效, 使用数据块更新 mu
            b_i = chunk_to_int(chunk)
            recomputed_mu = (recomputed_mu + v_i * b_i) % curve_order

        # 步骤 3: 检查重新计算的 mu 是否与证明中的 mu 匹配
        if recomputed_mu != proof.mu:
            return False  # 聚合数据块哈希 ('mu') 无效

        # 步骤 4: 执行最终的密码学检查
        return dPDP.CheckProof(params, proof, challenge)
