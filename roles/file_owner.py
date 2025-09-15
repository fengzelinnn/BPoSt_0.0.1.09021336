import random
from typing import List, Tuple

from common.datastructures import FileChunk, DPDPParams, DPDPTags
from Crypto.dpdp import dPDP
from utils import log_msg

class FileOwner:
    """文件所有者：代表一个寻求在网络上存储文件的用户。"""

    def __init__(self, owner_id: str, chunk_size: int):
        """
        初始化文件所有者。
        """
        self.owner_id = owner_id
        self.chunk_size = chunk_size
        self.params: DPDPParams = dPDP.KeyGen()
        self.tags: DPDPTags = DPDPTags(tags=[])
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
