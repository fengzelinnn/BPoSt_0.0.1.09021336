"""
BPoSt协议定义

该模块整合了BPoSt（基于区块链的存储时间证明）共识协议的所有核心数据结构和协议特定逻辑。

它作为协议定义的唯一真实来源，包括：
- 区块、分片和证明的数据结构。
- 状态管理结构，如默克尔树和多维状态树。
- 用于dPDP的密码学逻辑。

通过集中化这些定义，我们提高了模块化和可读性，明确了协议的“语言”与使用它的“参与者”之间的区别。
"""
import random
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

from crypto import G1Element, Scalar
from merkle import MerkleTree
from utils import h_join, sha256_hex

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

@dataclass
class PublicKey:
    """dPDP公钥，包含BLS12-381曲线的公共参数。"""
    beta: G1Element  # beta = g^alpha

    def to_dict(self) -> dict:
        """将公钥序列化为字典。"""
        return {'beta': repr(self.beta)}

    @classmethod
    def from_dict(cls, data: dict) -> 'PublicKey':
        """从字典反序列化公钥。"""
        beta_repr = data['beta']
        try:
            parts = beta_repr.split('(')[1].split(')')[0].split(',')
            beta = G1Element(int(parts[0]), int(parts[1]))
        except (IndexError, ValueError):
            parts = beta_repr.split('(')[1].split(')')[0].split(',')
            beta = G1Element(int(parts[0]), int(parts[1].strip()))
        return cls(beta=beta)

@dataclass
class FileChunk:
    """一个文件分片，由客户端准备并附带dPDP签名。"""
    index: int
    data: bytes
    signature: G1Element  # sigma_i = (H(i) * u^b_i)^alpha
    file_id: str

    def to_dict(self) -> dict:
        """序列化为字典，将密码学元素转换为字符串表示。"""
        return {
            'index': self.index,
            'data': self.data.hex(),
            'signature': repr(self.signature),
            'file_id': self.file_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'FileChunk':
        """从字典反序列化，从字符串表示恢复密码学元素。"""
        sig_repr = data['signature']
        try:
            parts = sig_repr.split('(')[1].split(')')[0].split(',')
            signature = G1Element(int(parts[0]), int(parts[1]))
        except (IndexError, ValueError):
            parts = sig_repr.split('(')[1].split(')')[0].split(',')
            signature = G1Element(int(parts[0]), int(parts[1].strip()))

        return cls(
            index=data['index'],
            data=bytes.fromhex(data['data']),
            signature=signature,
            file_id=data['file_id']
        )

@dataclass
class BobtailProof:
    """单次Bobtail PoW挖矿尝试的结果，现在包含一个dPDP证明。"""
    node_id: str
    address: str
    root: str
    nonce: str
    proof_hash: str
    lots: str
    file_roots: Dict[str, str] = field(default_factory=dict)

    # dPDP proof components
    file_id: str           # 证明针对的文件ID
    miu: Scalar            # 聚合的块内容: miu = sum(v_i * b_i)
    sigma: G1Element       # 聚合的签名: sigma = product(sigma_i ^ v_i)

    def to_dict(self) -> dict:
        d = asdict(self)
        if isinstance(d.get('root'), bytes): d['root'] = d['root'].hex()
        if isinstance(d.get('proof_hash'), bytes): d['proof_hash'] = d['proof_hash'].hex()
        if d.get('file_roots'):
            d['file_roots'] = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in d['file_roots'].items()}
        
        d['miu'] = self.miu.value
        d['sigma'] = repr(self.sigma)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> 'BobtailProof':
        """从字典反序列化，从字符串表示恢复密码学元素。"""
        data_copy = data.copy()
        miu = Scalar(data_copy.pop('miu'))
        sigma_repr = data_copy.pop('sigma')
        try:
            parts = sigma_repr.split('(')[1].split(')')[0].split(',')
            sigma = G1Element(int(parts[0]), int(parts[1]))
        except (IndexError, ValueError):
            parts = sigma_repr.split('(')[1].split(')')[0].split(',')
            sigma = G1Element(int(parts[0]), int(parts[1].strip()))

        return cls(miu=miu, sigma=sigma, **data_copy)

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
