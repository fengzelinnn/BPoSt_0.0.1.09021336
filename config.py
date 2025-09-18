from dataclasses import dataclass

@dataclass
class P2PSimConfig:
    """P2P模拟的配置参数"""
    num_nodes: int = 15
    num_file_owners: int = 5
    sim_duration_sec: int = 90
    chunk_size: int = 1024
    min_file_kb: int = 16
    max_file_kb: int = 24
    min_storage_nodes: int = 4
    max_storage_nodes: int = 8
    base_port: int = 62000
    bobtail_k: int = 3
    min_storage_kb: int = 512
    max_storage_kb: int = 2048
    bid_wait_sec: int = 15
