"""
分布式可证明数据持有（dPDP）桩实现

提供与指南一致的API外形：
- KeyGen -> (pk, sk)：返回 DPDPParams（模拟公私钥及群参数）。
- TagFile -> DPDPTags：为文件块生成标签（模拟 σ_i）。
- GenProof -> (pf_hash, per_idx)：基于挑战索引聚合生成证明哈希（模拟 (μ, σ)）。
- CheckProof -> bool：公开可验证，使用同一过程重算并对比。

说明：
为演示流程与接口联动，使用抗碰撞哈希代替双线性群与配对等真实密码学操作。
"""
from dataclasses import dataclass
from typing import List, Dict, Tuple

from utils import h_join, sha256_hex


@dataclass
class DPDPParams:
    g: str
    u: str
    pk_beta: str  # public key element (mock)
    sk_alpha: str  # secret key (mock)


@dataclass
class DPDPTags:
    tags: Dict[int, str]  # index -> tag


class dPDP:
    """
    公开可验证的 PDP 风格接口（遵循指南的API外形）。
    本实现为基于抗碰撞哈希的密码学桩，保留以下接口：
      - KeyGen(1^k) -> (pk, sk)  以 DPDPParams 表示
      - TagFile(pk, sk, f) -> T_f (DPDPTags)
      - GenProof(pk, F, chal, V) -> pf 以哈希聚合近似 (μ, σ)
      - CheckProof(pk, chal, pf) -> {0,1}
    说明：
      - 不模拟配对，使用确定性哈希承诺，结合 Time State Tree 的叶子/索引实现公开验证。
    """

    @staticmethod
    def KeyGen(security: int = 256) -> DPDPParams:
        # In a real scheme, choose groups and alpha. Here we derive mock strings deterministically.
        g = h_join("g", str(security))
        u = h_join("u", str(security))
        sk_alpha = h_join("alpha", str(security))
        pk_beta = h_join("beta", sk_alpha)
        return DPDPParams(g=g, u=u, pk_beta=pk_beta, sk_alpha=sk_alpha)

    @staticmethod
    def TagFile(params: DPDPParams, file_chunks: List[bytes]) -> DPDPTags:
        tags: Dict[int, str] = {}
        for i, b in enumerate(file_chunks):
            # σ_i := H( "tag" || i || H(b) || pk_beta ) as a stand-in for [H1(i) * u^{b_i}]^α
            tags[i] = h_join("tag", str(i), sha256_hex(b), params.pk_beta)
        return DPDPTags(tags=tags)

    @staticmethod
    def GenProof(params: DPDPParams, tags: DPDPTags, chal_indices: List[int], round_salt: str) -> Tuple[
        str, Dict[int, str]]:
        # Aggregate a proof hash analogous to (mu, sigma). We expose per-index components for transparency.
        parts = ["dpdp", "salt", round_salt]
        per_idx: Dict[int, str] = {}
        for idx in chal_indices:
            sig = tags.tags.get(idx, h_join("missing", str(idx)))
            per_idx[idx] = sig
            parts.append(h_join("agg", str(idx), sig))
        pf_hash = h_join(*parts)
        return pf_hash, per_idx

    @staticmethod
    def CheckProof(params: DPDPParams, tags: DPDPTags, chal_indices: List[int], round_salt: str, pf_hash: str) -> bool:
        recomputed, _ = dPDP.GenProof(params, tags, chal_indices, round_salt)
        return recomputed == pf_hash
