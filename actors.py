"""
BPoSt协议中的参与者（Actors）

该模块定义了BPoSt协议中的主要参与者（或角色）。
这些类封装了网络中参与者的行为。

- Client: 代表文件所有者。其主要职责是准备要存储的文件，
  方法是将其分块并生成dPDP（动态可证明数据拥有权）标签。

- ServerNode: 代表存储节点。它处理存储分片、维护状态树、
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


class Client:
    """文件所有者：封装文件预处理流程。"""

    def __init__(self, client_id: str, chunk_size: int = 256):
        """
        初始化客户端。

        :param client_id: 客户端的唯一标识符。
        :param chunk_size: 文件分片的大小（字节）。
        """
        self.client_id = client_id
        self.chunk_size = chunk_size
        self.params: DPDPParams = dPDP.KeyGen()  # 生成dPDP的公私钥参数
        self.tags: DPDPTags = DPDPTags(tags={})
        self.file_id: str = f"file_{client_id}_{random.randint(0, 1_000_000)}"
        self.chunks: List[FileChunk] = []

    def chunk_file(self, data: bytes) -> List[bytes]:
        """按 chunk_size 将文件字节流切分为块列表。"""
        return [data[i:i + self.chunk_size] for i in range(0, len(data), self.chunk_size)]

    def dpdp_setup(self, file_bytes: bytes) -> List[FileChunk]:
        """
        执行dPDP预处理：切分文件并为每个分片生成标签。
        返回一个FileChunk对象列表，准备好被广播到网络。
        """
        # 1. 将原始文件数据切分成块
        raw_chunks = self.chunk_file(file_bytes)
        # 2. 为所有分片生成dPDP标签
        self.tags = dPDP.TagFile(self.params, raw_chunks)
        # 3. 创建FileChunk对象列表，包含数据、索引和标签
        self.chunks = [
            FileChunk(index=i, data=b, tag=self.tags.tags[i], file_id=self.file_id)
            for i, b in enumerate(raw_chunks)
        ]
        return self.chunks


class ServerNode:
    """
    存储节点：存储、证明和挖矿的核心逻辑。
    该类被P2PNode封装，以赋予其网络自治能力。
    """
    def __init__(self, node_id: str, store_prob: float = 0.8):
        """
        初始化服务器节点。

        :param node_id: 节点的唯一标识符。
        :param store_prob: 节点决定存储一个接收到的分片的概率。
        """
        self.node_id = node_id
        self.store_prob = store_prob  # 存储概率
        self.storage = ServerStorage()  # 节点的存储状态容器
        self.reward_address = f"addr:{node_id}"  # 挖矿奖励地址

    def receive_chunk(self, chunk: FileChunk):
        """接收一个文件分片，并根据存储概率决定是否保留它。"""
        if random.random() <= self.store_prob:
            # 如果决定存储，则计算并保存分片的承诺
            commitment = h_join("commit", chunk.tag, sha256_hex(chunk.data))
            self.storage.add_chunk_commitment(chunk.file_id, chunk.index, commitment)

    def finalize_initial_commitments(self):
        """在接收完一批分片后，构建或更新状态树。"""
        self.storage.build_state()

    def dpdp_prove(self, indices: List[int], round_salt: str, file_id: str) -> Tuple[str, Dict[int, str]]:
        """
        为指定文件的一组挑战索引生成dPDP聚合证明。
        (此为简化实现，实际dPDP涉及更复杂的密码学计算)
        返回: (聚合证明哈希, {索引: 对应的承诺}) 的元组。
        """
        time_root = self.storage.time_trees[file_id].root() if file_id in self.storage.time_trees else h_join('empty')
        storage_root = self.storage.storage_root()

        # 构造证明哈希的输入
        parts = ["node", self.node_id, "salt", round_salt, "sroot", storage_root, "f", file_id, time_root]
        per_index_commitments: Dict[int, str] = {}

        tst_leaves = self.storage.time_trees[file_id].leaves if file_id in self.storage.time_trees else {}

        for idx in indices:
            commit = tst_leaves.get(idx, h_join("missing", str(idx)))
            per_index_commitments[idx] = commit
            parts.append(h_join("idx", str(idx), commit))

        proof_hash = h_join(*parts)

        # (简化逻辑) 将本轮证明“折叠”进被挑战的时间状态树叶子节点，以模拟状态更新
        for idx in indices:
            prev_leaf = tst_leaves.get(idx, h_join("missing", str(idx)))
            new_leaf = h_join("tleaf", prev_leaf, proof_hash, round_salt)
            self.storage.add_chunk_commitment(file_id, idx, new_leaf)

        # 更新状态树以反映叶子节点的变更
        self.storage.build_state()
        log_msg("INFO", "VERIFY", self.node_id, f"为文件 {file_id} 生成了证明 {proof_hash[:16]}...")
        return proof_hash, per_index_commitments

    def mine_bobtail(self, seed: str, max_nonce: int = 8192) -> List[BobtailProof]:
        """
        执行Bobtail PoW（工作量证明）挖矿。
        目标是找到一个nonce，使得哈希结果最小。
        返回: 一个包含单个最优 `BobtailProof` 对象的列表。
        """
        root = self.storage.storage_root()
        if isinstance(root, bytes):
            root = root.hex()

        file_roots = {}
        if self.storage.storage_tree and self.storage.storage_tree.file_roots:
            file_roots = self.storage.storage_tree.file_roots

        best_hash = ""
        best_nonce = -1

        # 迭代nonce以寻找最小哈希值
        for nonce in range(max_nonce):
            h = sha256_hex(f"bobtail|{seed}|{root}|{self.node_id}|{nonce}".encode())
            if best_hash == "" or h < best_hash:
                best_hash = h
                best_nonce = nonce

        # 构建并返回最优解的证明
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
