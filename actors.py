"""
BPoSt协议中的参与者（Actors）

该模块定义了BPoSt协议中的主要参与者（或角色），并实现了dPDP方案的核心密码学逻辑。
"""
import random
import threading
from typing import List, Tuple, Dict

from crypto import (
    G1Element, G2Element, Scalar,
    g1_generator, g2_generator, G1_IDENTITY,
    random_scalar, hash_to_scalar, hash_to_g1,
    add, multiply, pairing, CURVE_ORDER
)
from protocol import (
    FileChunk,
    BobtailProof,
    PublicKey
)
from utils import h_join, sha256_hex, log_msg


class FileOwner:
    """文件所有者：代表一个寻求在网络上存储文件的用户。"""

    def __init__(self, owner_id: str, chunk_size: int):
        self.owner_id = owner_id
        self.chunk_size = chunk_size
        self.file_id: str = f"file_{owner_id}_{random.randint(0, 1_000_000)}"
        
        self.sk_alpha: Scalar = random_scalar()
        self.pk_beta: G2Element = multiply(g2_generator, self.sk_alpha)
        self.public_key = PublicKey(beta=self.pk_beta)

    def create_file(self, size_bytes: int) -> bytes:
        return random.randbytes(size_bytes)

    def split_file(self, data: bytes) -> List[bytes]:
        return [data[i:i + self.chunk_size] for i in range(0, len(data), self.chunk_size)]

    def sign_file(self, file_bytes: bytes) -> Tuple[List[FileChunk], Dict]:
        raw_chunks = self.split_file(file_bytes)
        num_chunks = len(raw_chunks)
        log_msg("DEBUG", "OWNER", self.owner_id, f"为 {self.file_id} 的 {num_chunks} 个块生成签名...")

        u = g1_generator
        chunks = []
        for i, b_data in enumerate(raw_chunks):
            b_i = int.from_bytes(b_data, 'big')
            h_i = hash_to_g1(str(i).encode())
            u_pow_b = multiply(u, b_i)
            term = add(h_i, u_pow_b)
            signature = multiply(term, self.sk_alpha)
            chunks.append(FileChunk(index=i, data=b_data, signature=signature, file_id=self.file_id))

        metadata = {
            "public_key": self.public_key.to_dict(),
            "num_chunks": num_chunks,
        }
        return chunks, metadata

    def prepare_storage_request(
        self, min_size_bytes: int, max_size_bytes: int, num_nodes: int
    ) -> Tuple[List[FileChunk], int, Dict]:
        file_size = random.randint(min_size_bytes, max_size_bytes)
        file_bytes = self.create_file(file_size)
        chunks, metadata = self.sign_file(file_bytes)
        log_msg("INFO", "OWNER", self.owner_id, f"为文件 {self.file_id} 生成了 {len(chunks)} 个数据块和签名")
        return chunks, num_nodes, metadata


class StorageNode:
    """
    存储节点：存储、证明和挖矿的核心逻辑。
    """
    def __init__(self, node_id: str, chunk_size: int, max_storage: int):
        self.node_id = node_id
        self.chunk_size = chunk_size
        self.reward_address = f"addr:{node_id}"
        self.max_storage = max_storage
        self.used_space = 0
        self.state_lock = threading.Lock()
        self.chunks: Dict[str, Dict[int, FileChunk]] = {}
        self.file_metadata: Dict[str, Dict] = {}

    def __getstate__(self):
        """在序列化（pickling）时，排除不可序列化的锁。"""
        state = self.__dict__.copy()
        del state['state_lock']
        return state

    def __setstate__(self, state):
        """在反序列化（unpickling）后，重新创建锁。"""
        self.__dict__.update(state)
        self.state_lock = threading.Lock()

    def num_files(self) -> int:
        """返回此节点正在存储的文件数量。"""
        with self.state_lock:
            return len(self.chunks)

    def can_store(self, size: int) -> bool:
        return self.used_space + size <= self.max_storage

    def receive_chunk(self, chunk: FileChunk, metadata: Dict) -> bool:
        with self.state_lock:
            if not self.can_store(self.chunk_size):
                return False
            file_id = chunk.file_id
            if file_id not in self.chunks:
                self.chunks[file_id] = {}
                self.file_metadata[file_id] = metadata
            self.chunks[file_id][chunk.index] = chunk
            self.used_space += self.chunk_size
            return True

    def finalize_initial_commitments(self):
        pass

    def generate_dpop_proof(self, file_id: str, seed: str) -> Tuple[Scalar, G1Element]:
        metadata = self.file_metadata[file_id]
        m = metadata['num_chunks']
        a = int(m**0.5) + 1
        challenge_seed = (seed + file_id).encode()
        i_base = hash_to_scalar(challenge_seed) % (m // a)
        chal_indices = [(i_base + j * (m // a)) for j in range(a)]
        chal_vs = [hash_to_scalar((str(i) + seed).encode()) for i in chal_indices]
        
        miu = 0
        aggregated_sigma = G1_IDENTITY
        stored_chunks = self.chunks[file_id]

        for i, v_i in zip(chal_indices, chal_vs):
            if i in stored_chunks:
                chunk = stored_chunks[i]
                b_i = int.from_bytes(chunk.data, 'big')
                sigma_i = chunk.signature
                miu = (miu + v_i * b_i) % CURVE_ORDER
                term = multiply(sigma_i, v_i)
                aggregated_sigma = add(aggregated_sigma, term)
        return miu, aggregated_sigma

    @staticmethod
    def verify_dpop_proof(proof: BobtailProof, metadata: Dict, seed: str) -> bool:
        pk = PublicKey.from_dict(metadata['public_key'])
        beta = pk.beta
        m = metadata['num_chunks']
        a = int(m**0.5) + 1

        challenge_seed = (seed + proof.file_id).encode()
        i_base = hash_to_scalar(challenge_seed) % (m // a)
        chal_indices = [(i_base + j * (m // a)) for j in range(a)]
        chal_vs = [hash_to_scalar((str(i) + seed).encode()) for i in chal_indices]

        prod_h_v = G1_IDENTITY
        for i, v_i in zip(chal_indices, chal_vs):
            h_i = hash_to_g1(str(i).encode())
            term = multiply(h_i, v_i)
            prod_h_v = add(prod_h_v, term)
        
        u = g1_generator
        u_pow_miu = multiply(u, proof.miu)
        right_base = add(prod_h_v, u_pow_miu)

        g = g2_generator
        left = pairing(proof.sigma, g)
        right = pairing(right_base, beta)

        return left == right

    def mine_bobtail(self, seed: str, max_nonce: int = 8192) -> List[BobtailProof]:
        with self.state_lock:
            if not self.chunks: return []
            file_id_to_prove = random.choice(list(self.chunks.keys()))
            miu, sigma = self.generate_dpop_proof(file_id_to_prove, seed)

            root = sha256_hex(f"state_root_placeholder_for_{self.node_id}".encode())
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
                nonce=str(best_nonce),
                proof_hash=best_hash,
                lots=str(max(1, len(self.chunks))),
                file_id=file_id_to_prove,
                miu=miu,
                sigma=sigma,
                file_roots={}
            )
            return [proof]
