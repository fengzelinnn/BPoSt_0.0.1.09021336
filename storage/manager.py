import threading
from typing import Dict, Tuple, List

from py_ecc.optimized_bls12_381 import FQ
from py_ecc.bls.g2_primitives import G1_to_pubkey

from common.datastructures import FileChunk, DPDPTags, DPDPProof
from storage.state import ServerStorage
from utils import h_join, sha256_hex, log_msg

class StorageManager:
    """
    管理节点的存储、状态树和原始文件数据。
    """
    def __init__(self, node_id: str, chunk_size: int, max_storage: int):
        self.node_id = node_id
        self.chunk_size = chunk_size
        self.max_storage = max_storage
        
        self.storage = ServerStorage()
        self.files: Dict[str, Dict[int, Tuple[bytes, Tuple[FQ, FQ, FQ]]]] = {}
        self.used_space = 0
        self.state_lock = threading.Lock()

    def __getstate__(self):
        state = self.__dict__.copy()
        if 'state_lock' in state:
            del state['state_lock']
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.state_lock = threading.Lock()

    def can_store(self, size: int) -> bool:
        with self.state_lock:
            return self.used_space + size <= self.max_storage

    def receive_chunk(self, chunk: FileChunk) -> bool:
        with self.state_lock:
            if self.used_space + self.chunk_size > self.max_storage:
                log_msg("WARN", "STORE", self.node_id, f"拒绝存储文件块 {chunk.file_id}[{chunk.index}]：存储空间不足。")
                return False

            self.files.setdefault(chunk.file_id, {})[chunk.index] = (chunk.data, chunk.tag)

            commitment = h_join("commit", str(chunk.tag), sha256_hex(chunk.data))
            self.storage.add_chunk_commitment(chunk.file_id, chunk.index, commitment)
            self.used_space += self.chunk_size
            return True

    def finalize_commitments(self):
        with self.state_lock:
            self.storage.build_state()
            log_msg("INFO", "COMMIT", self.node_id, f"已为接收的文件块构建状态树")

    def get_storage_root(self) -> str:
        with self.state_lock:
            return self.storage.storage_root()

    def get_file_roots(self) -> Dict[str, str]:
        with self.state_lock:
            if self.storage.storage_tree:
                return self.storage.storage_tree.file_roots
            return {}

    def get_num_files(self) -> int:
        with self.state_lock:
            return self.storage.num_files()
            
    def get_file_data_for_proof(self, file_id: str) -> Tuple[Dict[int, bytes], DPDPTags]:
        with self.state_lock:
            if file_id not in self.files:
                raise ValueError(f"文件 {file_id} 未找到，无法获取证明数据。")
            
            file_data = self.files[file_id]
            chunks = {idx: data for idx, (data, tag) in file_data.items()}
            all_tags_sorted = [tag for idx, (_, tag) in sorted(file_data.items())]
            tags = DPDPTags(tags=all_tags_sorted)
            
            return chunks, tags

    def update_state_after_proof(self, file_id: str, indices: List[int], proof: DPDPProof, round_salt: str):
        with self.state_lock:
            proof_hash_for_post = sha256_hex(G1_to_pubkey(proof.sigma) + str(proof.mu).encode())
            tst_leaves = self.storage.time_trees.get(file_id, None)
            if tst_leaves:
                for idx in indices:
                    prev_leaf = tst_leaves.leaves.get(idx, h_join("missing", str(idx)))
                    new_leaf = h_join("tleaf", prev_leaf, proof_hash_for_post, round_salt)
                    self.storage.add_chunk_commitment(file_id, idx, new_leaf)
                
                self.storage.build_state()
                log_msg("DEBUG", "PoSt", self.node_id, f"使用证明哈希 {proof_hash_for_post[:16]} 更新了文件 {file_id} 的时间状态...")
