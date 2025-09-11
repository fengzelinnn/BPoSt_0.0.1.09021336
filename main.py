"""
BPoSt P2P模拟入口点

该脚本初始化并运行BPoSt协议的主要模拟。

模拟环境是基于一个自定义的点对点（P2P）层构建的，
该层使用Python原生线程和套接字实现，定义在 `threadnet.py` 中。

要运行模拟，请直接执行此文件：

    python main.py

模拟将执行以下操作：
1.  在单独的线程中启动可配置数量的自治P2P节点。
2.  使用引导机制进行去中心化的对等节点发现。
3.  模拟用户（FileOwner）创建随机大小的文件，并指定随机数量的存储节点。
4.  模拟器将文件块直接分发给被选中的节点，模拟竞争过程。
5.  节点将自主地进行挖矿、生产和交换区块，以达成共识。
6.  最后，执行最终分析，检查节点之间的链共识情况。
"""

from threadnet import run_p2p_simulation, P2PSimConfig
from utils import init_logging

if __name__ == "__main__":
    # 日志记录将在每个子进程中首次需要时自动初始化，
    # 以避免在主进程中创建不可序列化的日志处理程序。

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
        max_storage_nodes=8,        # 用户请求的最多存储节点数
        base_port=41000,            # 节点监听的起始端口号
        bobtail_k=3                 # Bobtail共识需要的证明数量
    )

    # 运行主P2P模拟。
    run_p2p_simulation(config)
