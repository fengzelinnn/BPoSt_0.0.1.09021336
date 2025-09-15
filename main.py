"""
BPoSt P2P模拟入口点

该脚本初始化并运行BPoSt协议的主要模拟。
"""

from config import P2PSimConfig
from simulation import run_p2p_simulation

if __name__ == "__main__":
    # 创建一个模拟配置对象。
    # 您可以修改这些参数来改变模拟的规模和行为。
    config = P2PSimConfig(
        num_nodes=15,               # 网络中的节点总数
        num_file_owners=5,          # 发起存储请求的用户数量
        sim_duration_sec=9000,        # 文件分发后的共识模拟运行时长（秒）
        chunk_size=16,             # 文件分片大小（字节）
        min_file_kb=1,             # 用户生成的最小文件大小（KB）
        max_file_kb=2,            # 用户生成的最大文件大小（KB）
        min_storage_nodes=4,        # 用户请求的最少存储节点数
        max_storage_nodes=5,        # 用户请求的最多存储节点数
        base_port=62000,            # 节点监听的起始端口号
        bobtail_k=3                 # Bobtail共识需要的证明数量
    )

    # 运行主P2P模拟。
    run_p2p_simulation(config)
