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
import threading
from typing import List, Tuple, Dict

from protocol import (
    FileChunk,
    ServerStorage,
    dPDP,
    DPDPParams,
    DPDPTags,
    DPDPProof, # Import the new proof structure
    BobtailProof,
    curve_order # Import for generating challenge coefficients
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
        self.params: DPDPParams = dPDP.KeyGen()  # Generates real BLS keys now
        self.tags: DPDPTags = DPDPTags(tags={})
        self.file_id: str = f"file_{owner_id}_{random.randint(0, 1_000_000)}"

    def get_dpdp_params(self) -> DPDPParams:
        """返回dPDP参数，以便验证者可以验证证明。"""
        return self.params

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
        # TagFile now generates real BLS-based tags
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
        log_msg("INFO", "OWNER", self.owner_id, f"为文件 {self.file_id} 生成了 {len(chunks)} 个数据块和dPDP标签")

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
        # New storage for raw data and tags, required for proof generation
        self.files: Dict[str, Dict[int, Tuple[bytes, str]]] = {}
        self.state_lock = threading.Lock() # 确保状态修改的原子性

    def __getstate__(self):
        """自定义Pickle行为，以允许在多进程中使用。"""
        state = self.__dict__.copy()
        del state['state_lock']
        return state

    def __setstate__(self, state):
        """在反序列化后，重新创建锁对象。"""
        self.__dict__.update(state)
        self.state_lock = threading.Lock()

    def can_store(self, size: int) -> bool:
        """检查节点是否有足够的空间来存储指定大小的数据。"""
        return self.used_space + size <= self.max_storage

    def receive_chunk(self, chunk: FileChunk) -> bool:
        """
        接收并存储一个文件分片，前提是有足够的可用空间。
        """
        with self.state_lock:
            if not self.can_store(self.chunk_size):
                log_msg("WARN", "STORE", self.node_id, f"拒绝存储文件块 {chunk.file_id}[{chunk.index}]：存储空间不足。")
                return False

            # Store the raw data and tag for dPDP proofs
            self.files.setdefault(chunk.file_id, {})[chunk.index] = (chunk.data, chunk.tag)

            # The commitment for the PoSt TimeStateTree remains the same
            commitment = h_join("commit", chunk.tag, sha256_hex(chunk.data))
            self.storage.add_chunk_commitment(chunk.file_id, chunk.index, commitment)
            self.used_space += self.chunk_size
            return True

    def finalize_initial_commitments(self):
        """在接收完一批分片后，构建或更新状态树。"""
        with self.state_lock:
            self.storage.build_state()
            log_msg("INFO", "COMMIT", self.node_id, f"已为接收的文件块构建状态树")

    def dpdp_prove(self, indices: List[int], round_salt: str, file_id: str) -> Tuple[DPDPProof, List[Tuple[int, int]]]:
        """
        为指定的挑战生成dPDP聚合证明，并更新PoSt状态树。
        返回真实的dPDP证明和用于验证的挑战。
        """
        with self.state_lock:
            if file_id not in self.files:
                raise ValueError(f"文件 {file_id} 未找到，无法生成证明。")

            # 1. 生成完整的dPDP挑战（包括随机系数）
            challenge = [(i, random.randint(1, curve_order - 1)) for i in indices]

            # 2. 准备dPDP.GenProof所需的数据
            # GenProof needs a dictionary of chunks and a DPDPTags object
            challenged_chunks = {i: self.files[file_id][i][0] for i, _ in challenge if i in self.files[file_id]}
            tag_dict = {idx: tag for idx, (_, tag) in self.files[file_id].items()}
            tags = DPDPTags(tags=tag_dict)

            # 3. 调用真实的dPDP证明生成
            proof = dPDP.GenProof(tags, challenged_chunks, challenge)
            log_msg("DEBUG", "dPDP", self.node_id, f"为文件 {file_id} 生成了dPDP证明")

            # 4. (PoSt) 更新TimeStateTree，使用新生成的真实证明的哈希
            proof_hash_for_post = sha256_hex(proof.sigma.encode() + str(proof.mu).encode())
            tst_leaves = self.storage.time_trees.get(file_id, None)
            if tst_leaves:
                for idx in indices:
                    prev_leaf = tst_leaves.leaves.get(idx, h_join("missing", str(idx)))
                    new_leaf = h_join("tleaf", prev_leaf, proof_hash_for_post, round_salt)
                    self.storage.add_chunk_commitment(file_id, idx, new_leaf)
                
                self.storage.build_state()
                log_msg("DEBUG", "PoSt", self.node_id, f"使用证明哈希 {proof_hash_for_post[:16]} 更新了文件 {file_id} 的时间状态...")

            # 5. 返回真实的证明和挑战，以供验证者使用
            return proof, challenge

    def mine_bobtail(self, seed: str, max_nonce: int = 8192) -> List[BobtailProof]:
        """
        执行Bobtail PoW（工作量证明）挖矿。
        """
        with self.state_lock:
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
