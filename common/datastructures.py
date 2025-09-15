from dataclasses import dataclass, field, asdict
from typing import Dict, List, Tuple

from py_ecc.optimized_bls12_381 import FQ


@dataclass
class BlockBody:
    """区块主体，包含交易和证明等。"""
    selected_k_proofs: List[Dict[str, str]] = field(default_factory=list)
    coinbase_splits: Dict[str, str] = field(default_factory=dict)
    proofs_merkle_tree: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'BlockBody':
        return cls(**data)


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
    body: BlockBody
    time_tree_roots: Dict[str, Dict[str, str]] = field(default_factory=dict)
    bobtail_k: int = 0
    bobtail_target: str = "0"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'Block':
        data['body'] = BlockBody.from_dict(data['body'])
        return cls(**data)

    def header_hash(self) -> str:
        """计算并返回区块头的哈希值。"""
        # 为避免循环依赖，实际哈希逻辑在工具函数中实现。
        pass


@dataclass
class FileChunk:
    """一个文件分片，由客户端准备并附带dPDP标签。"""
    index: int
    data: bytes
    tag: tuple[FQ, FQ, FQ]
    file_id: str = "default"

    def to_dict(self) -> dict:
        d = asdict(self)
        d['data'] = self.data.hex()
        # 注意：标签序列化由调用方处理
        return d

    @classmethod
    def from_dict(cls, data: dict) -> 'FileChunk':
        data['data'] = bytes.fromhex(data['data'])
        # 注意：标签反序列化由调用方处理
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
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'BobtailProof':
        return cls(**data)


@dataclass
class DPDPParams:
    """dPDP公共参数和所有者的私钥。"""
    g: tuple
    u: tuple
    pk_beta: tuple
    sk_alpha: int

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'DPDPParams':
        return cls(**data)


@dataclass
class DPDPTags:
    """一个文件的所有分片的dPDP标签。"""
    tags: list[tuple]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'DPDPTags':
        return cls(**data)


@dataclass
class DPDPProof:
    """针对给定挑战的dPDP证明。"""
    mu: int
    sigma: tuple

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'DPDPProof':
        return cls(**data)
