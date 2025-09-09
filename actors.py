"""
BPoSt协议中的参与者（Actors）

该模块定义了BPoSt协议中的主要参与者（或角色）。
这些类封装了网络中参与者的行为。

- FileOwner: 代表文件所有者（用户）。其主要职责是准备要存储的文件，
  指定存储需求，并对文件进行预处理（分块和生成dPDP标签）。

- StorageNode: 代表存储节点。它处理存储分片、维护状态树、
  生成证明和参与共识的核心逻辑。
"""
import random
from typing import List, Tuple, Dict

from protocol import (
    FileChunk,
    ServerStorage,
    dPDP,
    DPDPParams,
    DPDPTags,
    BobtailProof
)
from utils import h_join, sha256_hex, log_msg


class FileOwner:
    """文件所有者：代表一个寻求在网络上存储文件的用户。"""

    def __init__(self, owner_id: str, chunk_size: int):
        """
        初始化文件所有者。

        :param owner_id: 用户的唯一标识符。
        :param chunk_size: 文件分片的大小（字节）。
        """
        self.owner_id = owner_id
        self.chunk_size = chunk_size
        self.params: DPDPParams = dPDP.KeyGen()  # 生成dPDP的公私钥参数
        self.tags: DPDPTags = DPDPTags(tags={})
        self.file_id: str = f"file_{owner_id}_{random.randint(0, 1_000_000)}"

    def create_file(self, size_bytes: int) -> bytes:
        """创建一个具有指定大小的随机字节文件。"""
        return random.randbytes(size_bytes)

    def split_file(self, data: bytes) -> List[bytes]:
        """按 chunk_size 将文件字节流切分为块列表。"""
        return [data[i:i + self.chunk_size] for i in range(0, len(data), self.chunk_size)]

    def dpdp_setup(self, file_bytes: bytes) -> List[FileChunk]:
        """
        执行dPDP预处理：切分文件并为每个分片生成标签。
        返回一个FileChunk对象列表，准备好被广播到网络。
        """
        raw_chunks = self.split_file(file_bytes)
        self.tags = dPDP.TagFile(self.params, raw_chunks)
        chunks = [
            FileChunk(index=i, data=b, tag=self.tags.tags[i], file_id=self.file_id)
            for i, b in enumerate(raw_chunks)
        ]
        return chunks

    def prepare_storage_request(
        self, min_size_bytes: int, max_size_bytes: int, num_nodes: int
    ) -> Tuple[List[FileChunk], int]:
        """
        创建一个随机大小的文件，准备存储，并返回数据块和所需的存储节点数。
        """
        file_size = random.randint(min_size_bytes, max_size_bytes)
        file_bytes = self.create_file(file_size)
        log_msg("INFO", "OWNER", self.owner_id, f"创建了大小为 {file_size} 字节的随机文件 {self.file_id}")

        chunks = self.dpdp_setup(file_bytes)
        log_msg("INFO", "OWNER", self.owner_id, f"为文件 {self.file_id} 生成了 {len(chunks)} 个数据块和标签")

        return chunks, num_nodes


class StorageNode:
    """
    存储节点：存储、证明和挖矿的核心逻辑。
    该类被P2PNode封装，以赋予其网络自治能力。
    """
    def __init__(self, node_id: str, chunk_size: int, max_storage: int):
        """
        初始化存储节点。

        :param node_id: 节点的唯一标识符。
        :param chunk_size: 文件分片的大小（字节）。
        :param max_storage: 节点可用的最大存储空间（字节）。
        """
        self.node_id = node_id
        self.chunk_size = chunk_size
        self.storage = ServerStorage()
        self.reward_address = f"addr:{node_id}"
        self.max_storage = max_storage
        self.used_space = 0

    def can_store(self, size: int) -> bool:
        """检查节点是否有足够的空间来存储指定大小的数据。"""
        return self.used_space + size <= self.max_storage

    def receive_chunk(self, chunk: FileChunk) -> bool:
        """
        接收并存储一个文件分片，前提是有足够的可用空间。
        """
        if not self.can_store(self.chunk_size):
            log_msg("WARN", "STORE", self.node_id, f"拒绝存储文件块 {chunk.file_id}[{chunk.index}]：存储空间不足。")
            return False

        commitment = h_join("commit", chunk.tag, sha256_hex(chunk.data))
        self.storage.add_chunk_commitment(chunk.file_id, chunk.index, commitment)
        self.used_space += self.chunk_size
        # log_msg("INFO", "STORE", self.node_id, f"已存储文件块 {chunk.file_id}[{chunk.index}]。当前使用: {self.used_space // 1024}/{self.max_storage // 1024} KB")
        return True

    def finalize_initial_commitments(self):
        """在接收完一批分片后，构建或更新状态树。"""
        self.storage.build_state()
        log_msg("INFO", "COMMIT", self.node_id, f"已为接收的文件块构建状态树")

    def dpdp_prove(self, indices: List[int], round_salt: str, file_id: str) -> Tuple[str, Dict[int, str]]:
        """
        为指定文件的一组挑战索引生成dPDP聚合证明。
        """
        time_root = self.storage.time_trees[file_id].root() if file_id in self.storage.time_trees else h_join('empty')
        storage_root = self.storage.storage_root()

        parts = ["node", self.node_id, "salt", round_salt, "sroot", storage_root, "f", file_id, time_root]
        per_index_commitments: Dict[int, str] = {}

        tst_leaves = self.storage.time_trees[file_id].leaves if file_id in self.storage.time_trees else {}

        for idx in indices:
            commit = tst_leaves.get(idx, h_join("missing", str(idx)))
            per_index_commitments[idx] = commit
            parts.append(h_join("idx", str(idx), commit))

        proof_hash = h_join(*parts)

        for idx in indices:
            prev_leaf = tst_leaves.get(idx, h_join("missing", str(idx)))
            new_leaf = h_join("tleaf", prev_leaf, proof_hash, round_salt)
            self.storage.add_chunk_commitment(file_id, idx, new_leaf)

        self.storage.build_state()
        log_msg("DEBUG", "VERIFY", self.node_id, f"为文件 {file_id} 生成了证明 {proof_hash[:16]}...")
        return proof_hash, per_index_commitments

    def mine_bobtail(self, seed: str, max_nonce: int = 8192) -> List[BobtailProof]:
        """
        执行Bobtail PoW（工作量证明）挖矿。
        """
        root = self.storage.storage_root()
        if isinstance(root, bytes):
            root = root.hex()

        file_roots = self.storage.storage_tree.file_roots if self.storage.storage_tree else {}

        best_hash = ""
        best_nonce = -1

        for nonce in range(max_nonce):
            h = sha256_hex(f"bobtail|{seed}|{root}|{self.node_id}|{nonce}".encode())
            if best_hash == "" or h < best_hash:
                best_hash = h
                best_nonce = nonce

        if best_nonce == -1: return []

        proof = BobtailProof(
            node_id=self.node_id,
            address=self.reward_address,
            root=root,
            file_roots=file_roots,
            nonce=str(best_nonce),
            proof_hash=best_hash,
            lots=str(max(1, self.storage.num_files())),
        )
        return [proof]
