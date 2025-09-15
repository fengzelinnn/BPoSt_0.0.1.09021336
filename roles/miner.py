from typing import List, Dict

from common.datastructures import BobtailProof
from utils import sha256_hex

class Miner:
    """
    执行Bobtail PoW（工作量证明）挖矿。
    """
    def __init__(self, node_id: str, reward_address: str):
        self.node_id = node_id
        self.reward_address = reward_address

    def mine(self, seed: str, storage_root: str, file_roots: Dict[str, str], num_files: int, max_nonce: int = 8192) -> List[BobtailProof]:
        """
        执行一次PoW挖矿，尝试找到一个有效的Bobtail证明。

        :param seed: 用于挖矿的随机种子（通常是上一个区块的哈希）。
        :param storage_root: 节点当前存储状态的根哈希。
        :param file_roots: 每个文件的状态树根哈希。
        :param num_files: 节点存储的文件数量。
        :param max_nonce: 要尝试的最大nonce数。
        :return: 一个包含找到的Bobtail证明的列表，如果未找到则为空列表。
        """
        best_hash = ""
        best_nonce = -1

        for nonce in range(max_nonce):
            h = sha256_hex(f"bobtail|{seed}|{storage_root}|{self.node_id}|{nonce}".encode())
            if best_hash == "" or h < best_hash:
                best_hash = h
                best_nonce = nonce

        if best_nonce == -1:
            return []

        proof = BobtailProof(
            node_id=self.node_id,
            address=self.reward_address,
            root=storage_root,
            file_roots=file_roots,
            nonce=str(best_nonce),
            proof_hash=best_hash,
            lots=str(max(1, num_files)),
        )
        return [proof]
