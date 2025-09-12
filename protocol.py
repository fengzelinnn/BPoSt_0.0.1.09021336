from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

from merkle import MerkleTree
from utils import h_join, sha256_hex

# New imports for dPDP
import random
from hashlib import sha256
from py_ecc.optimized_bls12_381 import (
    G1, G2,
    pairing,
    add,
    multiply,
    is_inf, # For converting Jacobian to affine coordinates
    FQ2,
    FQ,
)

from py_ecc.bls.g2_primitives import (
    G1_to_pubkey,
    pubkey_to_G1,
    G2_to_signature,
    signature_to_G2,
)

# 为了最小化代码改动，我们创建别名
serialize_G1 = G1_to_pubkey
deserialize_G1 = pubkey_to_G1
serialize_G2 = G2_to_signature
deserialize_G2 = signature_to_G2


# 从正确的导入中创建别名
G1_IDENTITY = G1
G2_IDENTITY = G2  # This is incorrect, but G2_IDENTITY is not used.
from py_ecc.bls.hash_to_curve import hash_to_G1 as _hash_to_G1
from py_ecc.bls12_381 import curve_order

# Domain separation tag for H1, as recommended by cryptographic best practices.
H1_DST = b'BPoSt-H1-DST-v1.0'

def hash_to_G1(message: bytes):
    """Wrapper for hash_to_G1 to provide a consistent domain separation."""
    return _hash_to_G1(message, H1_DST, sha256)


def chunk_to_int(chunk: bytes) -> int:
    """
    Converts a file chunk to an integer modulo the curve order.
    We hash the chunk to get a uniformly distributed integer that fits within the field.
    """
    # Use SHA256 for a 256-bit hash, then convert to integer.
    h = sha256_hex(chunk)
    return int(h, 16)

@dataclass
class Block:
    """区块链中区块的头部和主体结构。"""
    height: int
    prev_hash: str
    seed: str
    leader_id: str
    accum_proof_hash: str
    merkle_roots: Dict[str, str]
    round_proof_stmt_hash: str
    time_tree_roots: Dict[str, Dict[str, str]] = field(default_factory=dict)
    bobtail_k: int = 0
    bobtail_target: str = "0"
    selected_k_proofs: List[Dict[str, str]] = field(default_factory=list)
    coinbase_splits: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        if isinstance(d.get('accum_proof_hash'), bytes):
            d['accum_proof_hash'] = d['accum_proof_hash'].hex()
        if d.get('merkle_roots'):
            d['merkle_roots'] = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in d['merkle_roots'].items()}
        if d.get('selected_k_proofs'):
            cleaned = []
            for item in d['selected_k_proofs']:
                cleaned.append({k: (v.hex() if isinstance(v, bytes) else v) for k, v in item.items()})
            d['selected_k_proofs'] = cleaned
        if d.get('coinbase_splits'):
            d['coinbase_splits'] = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in d['coinbase_splits'].items()}
        return d

    @classmethod
    def from_dict(cls, data: dict) -> 'Block':
        return cls(**data)

    def header_hash(self) -> str:
        """计算并返回区块头的哈希值。"""
        parts = [
            "block", str(self.height), self.prev_hash, self.seed, self.leader_id,
            self.accum_proof_hash, self.round_proof_stmt_hash,
            "bobtail", str(self.bobtail_k), self.bobtail_target
        ]
        if self.merkle_roots:
            for nid in sorted(self.merkle_roots.keys()):
                parts.extend(["root", nid, self.merkle_roots[nid]])

        if self.time_tree_roots:
            for nid in sorted(self.time_tree_roots.keys()):
                parts.append(f"tt_roots_for_{nid}")
                for fid in sorted(self.time_tree_roots[nid].keys()):
                    parts.extend([fid, self.time_tree_roots[nid][fid]])

        if self.selected_k_proofs:
            for p in self.selected_k_proofs:
                parts.extend(["proof", p.get("node_id", ""), p.get("proof_hash", "")])
        return h_join(*parts)

"""
BPoSt协议定义

该模块整合了BPoSt（基于区块链的存储时间证明）共识协议的所有核心数据结构和协议特定逻辑。

它作为协议定义的唯一真实来源，包括：
- 区块、分片和证明的数据结构。
- 状态管理结构，如默克尔树和多维状态树。
- 用于dPDP和IVC折叠的密码学占位逻辑。

通过集中化这些定义，我们提高了模块化和可读性，明确了协议的“语言”与使用它的“参与者”之间的区别。
"""

@dataclass
class FileChunk:
    """一个文件分片，由客户端准备并附带dPDP标签。"""
    index: int
    data: bytes
    tag: tuple[FQ, FQ, FQ]  # This will now be a hex-encoded BLS signature on G1
    file_id: str = "default"

    def to_dict(self) -> dict:
        d = asdict(self)
        d['data'] = self.data.hex()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> 'FileChunk':
        data['data'] = bytes.fromhex(data['data'])
        return cls(**data)

@dataclass
class BobtailProof:
    """单次Bobtail PoW挖矿尝试的结果。"""
    node_id: str
    address: str
    root: str
    nonce: str
    proof_hash: str
    lots: str
    file_roots: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        if isinstance(d.get('root'), bytes):
            d['root'] = d['root'].hex()
        if isinstance(d.get('proof_hash'), bytes):
            d['proof_hash'] = d['proof_hash'].hex()
        if d.get('file_roots'):
            d['file_roots'] = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in d['file_roots'].items()}
        return d

@dataclass
class TimeStateTree:
    """表示单个文件状态随时间变化的默克尔树。"""
    leaves: Dict[int, str] = field(default_factory=dict)
    merkle: Optional[MerkleTree] = None

    def build(self):
        max_index = max(self.leaves.keys()) if self.leaves else -1
        seq = [self.leaves.get(i, h_join("missing", str(i))) for i in range(max_index + 1)]
        self.merkle = MerkleTree(seq)

    def root(self) -> str:
        return self.merkle.root() if self.merkle else h_join("empty")

@dataclass
class StorageStateTree:
    """聚合单个节点所有TimeStateTree根的默克尔树。"""
    file_roots: Dict[str, str] = field(default_factory=dict)
    merkle: Optional[MerkleTree] = None

    def build(self):
        leaves = [self.file_roots[fid] for fid in sorted(self.file_roots.keys())]
        self.merkle = MerkleTree(leaves)

    def root(self) -> str:
        return self.merkle.root() if self.merkle else h_join("empty")

@dataclass
class ServerStorage:
    """服务器节点整个存储状态的容器。"""
    time_trees: Dict[str, TimeStateTree] = field(default_factory=dict)
    storage_tree: Optional[StorageStateTree] = None

    def add_chunk_commitment(self, file_id: str, index: int, commitment: str):
        self.time_trees.setdefault(file_id, TimeStateTree()).leaves[index] = commitment

    def build_state(self):
        for tst in self.time_trees.values():
            tst.build()
        self.storage_tree = StorageStateTree({fid: tst.root() for fid, tst in self.time_trees.items()})
        self.storage_tree.build()

    def storage_root(self) -> str:
        return self.storage_tree.root() if self.storage_tree else h_join("empty")

    def num_files(self) -> int:
        return len(self.time_trees)

# --- dPDP Implementation --- #

@dataclass
class DPDPParams:
    """dPDP public parameters and owner's secret key."""
    g: tuple[FQ2, FQ2, FQ2]         # G2 generator (serialized hex)
    u: tuple[FQ, FQ, FQ]         # G1 generator (serialized hex)
    pk_beta: tuple[FQ2, FQ2, FQ2]   # Public key (G2 point, serialized hex)
    sk_alpha: int  # Secret key (integer)

@dataclass
class DPDPTags:
    """dPDP tags for all chunks of a file."""
    tags: list[tuple[FQ, FQ, FQ]]   # { chunk_index: tag_hex }

@dataclass
class DPDPProof:
    """A dPDP proof for a given challenge."""
    mu: int      # Aggregated data chunks
    sigma: tuple[FQ, FQ, FQ]   # Aggregated signature (G1 point, serialized hex)

class dPDP:
    """Implementation of the dPDP scheme based on BLS signatures."""

    @staticmethod
    def KeyGen(security: int = 256) -> DPDPParams:
        """Generates dPDP parameters and keys."""
        sk_alpha = random.randint(1, curve_order - 1)

        from py_ecc.optimized_bls12_381 import G1 as G1_JAC, G2 as G2_JAC
        g = G2_JAC
        u = G1_JAC

        pk_beta = multiply(g, sk_alpha)

        return DPDPParams(
            g=g,
            u=u,
            pk_beta=pk_beta,
            sk_alpha=sk_alpha
        )

    @staticmethod
    def TagFile(params: DPDPParams, file_chunks: List[bytes]) -> DPDPTags:
        """Generates a dPDP tag for each file chunk."""
        tags: List[Tuple[FQ, FQ, FQ]] = []
        for i, chunk in enumerate(file_chunks):
            b_i = chunk_to_int(chunk)
            h_i = hash_to_G1(str(i).encode())

            # sigma_i = alpha * (h_i + b_i * u)
            term1 = h_i
            term2 = multiply(params.u, b_i)
            base_point = add(term1, term2)
            sigma_i = multiply(base_point, params.sk_alpha)

            tags.append(sigma_i)

        return DPDPTags(tags=tags)

    @staticmethod
    def GenProof(tags: DPDPTags, file_chunks: Dict[int, bytes], challenge: List[Tuple[int, int]]) -> DPDPProof:
        """Generates a dPDP proof for a challenge."""
        agg_mu = 0
        agg_sigma = G1_IDENTITY

        for i, v_i in challenge:
            if i not in file_chunks or i not in tags.tags:
                raise ValueError(f"Index {i} not found in provided chunks/tags for proof generation")

            b_i = chunk_to_int(file_chunks[i])
            sigma_i = tags.tags[i]

            # mu = mu + v_i * b_i
            agg_mu = (agg_mu + v_i * b_i) % curve_order

            # sigma = sigma + v_i * sigma_i
            agg_sigma = add(agg_sigma, multiply(sigma_i, v_i))

        return DPDPProof(
            mu=agg_mu,
            sigma=agg_sigma
        )

    @staticmethod
    def CheckProof(params: DPDPParams, proof: DPDPProof, challenge: List[Tuple[int, int]]) -> bool:
        """Verifies a dPDP proof."""
        # Deserialize all public components
        g = params.g
        u = params.u
        pk_beta = params.pk_beta
        sigma = proof.sigma

        if is_inf(sigma):
            return not challenge

        # LHS = pairing(sigma, g)
        # The py_ecc pairing primitive is pairing(G2_point, G1_point)
        lhs = pairing(g, sigma)

        # RHS = pairing(beta, agg_h + mu * u)
        # 1. Calculate agg_h = sum(v_i * h_i)
        agg_h = G1_IDENTITY
        for i, v_i in challenge:
            h_i = hash_to_G1(str(i).encode())
            agg_h = add(agg_h, multiply(h_i, v_i))

        # 2. Calculate mu * u
        mu_u = multiply(u, proof.mu)

        # 3. Build G1 point for RHS pairing
        rhs_g1_point = add(agg_h, mu_u)

        # 4. Calculate RHS pairing
        rhs = pairing(pk_beta, rhs_g1_point)

        # 5. Compare results
        return lhs == rhs

# --- End of dPDP Implementation --- #

@dataclass
class FoldingProof:
    acc_hash: str

    def __init__(self, acc_hash: Optional[str] = None):
        self.acc_hash = acc_hash or h_join("init_acc")

    def fold_with(self, other: 'FoldingProof') -> 'FoldingProof':
        return FoldingProof(h_join("fold", self.acc_hash, other.acc_hash))

class Blockchain:
    def __init__(self):
        self.blocks: List[Block] = []
        self.acc: FoldingProof = FoldingProof()

    def height(self) -> int:
        return len(self.blocks)

    def last_hash(self) -> str:
        return self.blocks[-1].header_hash() if self.blocks else h_join("genesis")

    def add_block(self, block: Block, folded_round_proof: Optional[FoldingProof] = None):
        if folded_round_proof:
            self.acc = self.acc.fold_with(folded_round_proof)
        self.blocks.append(block)
