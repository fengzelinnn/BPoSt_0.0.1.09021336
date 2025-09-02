"""
客户端（文件所有者）逻辑

- 负责文件分片、生成 dPDP 标签、向网络广播数据、按需请求证明、最终验证折叠证明。
"""
from typing import List, Tuple, Dict

from blockchain import Blockchain
from data import FileChunk
from dpdp import dPDP, DPDPParams, DPDPTags
from network import Network
from server import ServerNode


def verify_final(chain: Blockchain) -> bool:
    """最终验证：对链上累计折叠证明生成简洁证明并本地验证。"""
    if not chain.blocks:
        return False
    # 生成最终简洁证明 π_final
    pi_final = chain.acc.zk_prove()
    # 任何验证者都可仅依据公开的累加器哈希进行验证
    from folding import FoldingProof
    return FoldingProof.zk_verify(chain.acc.acc_hash, pi_final)


class Client:
    """文件所有者：封装文件预处理与验证流程。"""

    def __init__(self, client_id: str, chunk_size: int = 64):
        self.client_id = client_id
        self.chunk_size = chunk_size
        self.params: DPDPParams = dPDP.KeyGen()
        self.tags: DPDPTags = DPDPTags(tags={})
        self.file_id: str = f"file:{client_id}:0"
        self.chunks: List[FileChunk] = []

    def chunk_file(self, data: bytes) -> List[bytes]:
        """按 chunk_size 将文件字节流切分为块列表。"""
        blocks = []
        for i in range(0, len(data), self.chunk_size):
            blocks.append(data[i:i + self.chunk_size])
        return blocks

    def dpdp_setup(self, file_bytes: bytes) -> List[FileChunk]:
        """执行 dPDP 预处理：切分文件并生成每个分片的标签，返回 FileChunk 列表。"""
        raw_chunks = self.chunk_file(file_bytes)
        # 生成每个块的 dPDP 标签
        self.tags = dPDP.TagFile(self.params, raw_chunks)
        chunks: List[FileChunk] = []
        for i, b in enumerate(raw_chunks):
            tag = self.tags.tags[i]
            chunks.append(FileChunk(index=i, data=b, tag=tag, file_id=self.file_id))
        self.chunks = chunks
        return chunks

    def gossip_upload(self, network: Network):
        """将预处理后的分片通过网络广播给各存储节点（瞬时/兼容路径）。"""
        for ch in self.chunks:
            network.gossip_upload(ch)

    def gossip_upload_proc(self, env, network: Network):
        """SimPy 进程：逐个分片通过网络广播，内部触发 Network.gossip_upload_proc 并等待传播延迟。"""
        for ch in self.chunks:
            yield env.process(network.gossip_upload_proc(ch))

    def request_proof(self, node: ServerNode, indices: List[int], round_salt: str) -> Tuple[str, Dict[int, str]]:
        """向指定节点发起按需证明请求，返回聚合证明哈希与索引-叶子映射。"""
        return node.dpdp_prove(indices, round_salt, self.file_id)
