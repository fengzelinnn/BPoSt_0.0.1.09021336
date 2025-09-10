"""
BPoSt协议定义

该模块整合了BPoSt（基于区块链的存储时间证明）共识协议的所有核心数据结构和协议特定逻辑。
"""
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from crypto import (
    G1Element, G2Element, Scalar,
    serialize_g1, deserialize_g1,
    serialize_g2, deserialize_g2,
    serialize_scalar, deserialize_scalar
)
from merkle import MerkleTree
from utils import h_join

@dataclass
class Block:
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
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'Block':
        return cls(**data)

    def header_hash(self) -> str:
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

@dataclass
class PublicKey:
    """dPDP公钥, beta = g^alpha, 其中 g 在 G2 中。"""
    beta: G2Element

    def to_dict(self) -> dict:
        return {'beta': serialize_g2(self.beta)}

    @classmethod
    def from_dict(cls, data: dict) -> 'PublicKey':
        return cls(beta=deserialize_g2(data['beta']))

@dataclass
class FileChunk:
    """一个文件分片, 附带dPDP签名 sigma_i = (H(i) * u^b_i)^alpha。"""
    index: int
    data: bytes
    signature: G1Element
    file_id: str

    def to_dict(self) -> dict:
        return {
            'index': self.index,
            'data': self.data.hex(),
            'signature': serialize_g1(self.signature),
            'file_id': self.file_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'FileChunk':
        return cls(
            index=data['index'],
            data=bytes.fromhex(data['data']),
            signature=deserialize_g1(data['signature']),
            file_id=data['file_id']
        )

@dataclass
class BobtailProof:
    """Bobtail PoW结果, 包含dPDP证明。"""
    # Fields without default values must come first
    node_id: str
    address: str
    root: str
    nonce: str
    proof_hash: str
    lots: str
    file_id: str
    miu: Scalar
    sigma: G1Element
    
    # Fields with default values must come after
    file_roots: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        # Manually serialize crypto types on top of the base dataclass dict
        base_dict = asdict(self)
        base_dict['miu'] = serialize_scalar(self.miu)
        base_dict['sigma'] = serialize_g1(self.sigma)
        return base_dict

    @classmethod
    def from_dict(cls, data: dict) -> 'BobtailProof':
        data_copy = data.copy()
        # Manually deserialize crypto types before passing to constructor
        data_copy['miu'] = deserialize_scalar(data_copy['miu'])
        data_copy['sigma'] = deserialize_g1(data_copy['sigma'])
        return cls(**data_copy)

# ... (TimeStateTree, StorageStateTree, etc. remain unchanged) ...
@dataclass
class TimeStateTree:
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
    file_roots: Dict[str, str] = field(default_factory=dict)
    merkle: Optional[MerkleTree] = None
    def build(self):
        leaves = [self.file_roots[fid] for fid in sorted(self.file_roots.keys())]
        self.merkle = MerkleTree(leaves)
    def root(self) -> str:
        return self.merkle.root() if self.merkle else h_join("empty")

@dataclass
class ServerStorage:
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
