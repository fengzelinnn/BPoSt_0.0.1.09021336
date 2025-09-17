import random
from hashlib import sha256
from typing import List, Dict, Tuple

from py_ecc.optimized_bn128 import (
    FQ,
    G1, G2,
    pairing,
    add,
    multiply,
    is_inf,
    Z1
)

from common.datastructures import DPDPParams, DPDPTags, DPDPProof
from utils import sha256_hex
from merkle import MerkleTree
from crypto import CURVE_ORDER as curve_order  # 使用 BN128 曲线阶

G1_IDENTITY = Z1

# 对 BN128：使用简化的 hash-to-G1（哈希为标量后乘 G1）
def hash_to_G1(message: bytes):
    k = int.from_bytes(sha256(message).digest(), "big") % curve_order
    return multiply(G1, k)

def chunk_to_int(chunk: bytes) -> int:
    """
    将文件块转换为模曲线阶的整数。
    """
    h = sha256_hex(chunk)
    return int(h, 16)

class dPDP:
    """基于 BLS 签名的 dPDP 方案实现."""

    @staticmethod
    def key_gen(security: int = 256) -> DPDPParams:
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
    def tag_file(params: DPDPParams, file_chunks: List[bytes]) -> DPDPTags:
        """为每个文件块生成 dPDP 标签."""
        tags: List[Tuple[FQ, FQ, FQ]] = []
        for i, chunk in enumerate(file_chunks):
            b_i = chunk_to_int(chunk)
            b_i %= curve_order
            h_i = hash_to_G1(str(i).encode())
            term1 = h_i
            term2 = multiply(params.u, int(b_i))
            base_point = add(term1, term2)
            sigma_i = multiply(base_point, int(params.sk_alpha))
            tags.append(sigma_i)
        return DPDPTags(tags=tags)
    
    @staticmethod
    def gen_chal(prev_hash: str, timestamp: int, tags: DPDPTags, m: int | None = None) -> List[Tuple[int, int]]:
        """
        依据(prev_hash, timestamp)确定性生成公开挑战集合。
        返回[(i, v_i)]，其中 i∈[0,n)，v_i∈Z_r。
        """
        n = len(tags.tags)
        if n == 0:
            return []
        count = m if m is not None else max(1, (timestamp % n) or 5)
        chal: List[Tuple[int, int]] = []
        for j in range(count):
            seed = f"{prev_hash}:{timestamp}:{j}".encode()
            i = int(sha256(seed).hexdigest(), 16) % n
            v_i = int(sha256(b"chal|" + seed).hexdigest(), 16) % curve_order
            chal.append((i, v_i))
        return chal

    @staticmethod
    def gen_contributions(tags: DPDPTags, file_chunks: Dict[int, bytes], challenge: List[Tuple[int, int]]) -> List[Tuple[int, int, Tuple[FQ, FQ, FQ]]]:
        """
        生成未聚合的分片贡献 (i, mu_i, sigma_i) 列表，其中
        mu_i = v_i * b_i (mod r), sigma_i = v_i * tag_i。
        """
        contributions: List[Tuple[int, int, Tuple[FQ, FQ, FQ]]] = []
        for i, v_i in challenge:
            if i >= len(tags.tags) or i not in file_chunks:
                raise ValueError(f"索引 {i} 在提供的块/标签中未找到，无法生成贡献")
            b_i = chunk_to_int(file_chunks[i]) % curve_order
            sigma_i = tuple(int(x) for x in tags.tags[i])
            sigma_i = tuple(FQ(x) for x in sigma_i)
            mu_i = (v_i * b_i) % curve_order
            sigma_i_scaled = multiply(sigma_i, v_i)
            contributions.append((i, mu_i, sigma_i_scaled))
        return contributions

    @staticmethod
    def gen_proof(tags: DPDPTags, file_chunks: Dict[int, bytes], challenge: List[Tuple[int, int]]) -> DPDPProof:
        """为挑战生成 dPDP 聚合证明。"""
        agg_mu = 0
        agg_sigma = G1_IDENTITY
        for i, v_i in challenge:
            if i >= len(tags.tags):
                raise ValueError(f"索引 {i} 在提供的块/标签中未找到，无法生成证明")
            b_i = chunk_to_int(file_chunks[i])
            sigma_i = tuple(int(x) for x in tags.tags[i])
            sigma_i = tuple(FQ(x) for x in sigma_i)
            agg_mu = (agg_mu + (v_i * (b_i % curve_order))) % curve_order
            agg_sigma = add(agg_sigma, multiply(sigma_i, int(v_i)))
        return DPDPProof(mu=agg_mu, sigma=agg_sigma)

    @staticmethod
    def check_proof(params: DPDPParams, proof: DPDPProof, challenge: List[Tuple[int, int]]) -> bool:
        """验证 dPDP 证明."""
        sigma = tuple(int(x) for x in proof.sigma)
        sigma = tuple(FQ(x) for x in sigma)
        if is_inf(sigma):
            return not challenge
        lhs = pairing(params.g, sigma)
        agg_h = G1_IDENTITY
        for i, v_i in challenge:
            h_i = hash_to_G1(str(i).encode())
            agg_h = add(agg_h, multiply(h_i, int(v_i)))
        u = tuple(int(x) for x in params.u)
        u = tuple(FQ(x) for x in u)
        mu_u = multiply(u, int(proof.mu))
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
        return dPDP.check_proof(params, proof, challenge)
