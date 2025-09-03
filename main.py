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
3.  模拟客户端（文件所有者）创建文件并将其通过gossip协议广播到网络。
4.  运行一段固定的时间，在此期间节点将自主地进行挖矿、生产和交换区块，以达成共识。
5.  最后，它将执行最终分析，以检查节点之间的链共识情况。
"""

from threadnet import run_p2p_simulation, P2PSimConfig
from utils import init_logging

if __name__ == "__main__":
    # 初始化日志记录，输出到文件（bpst.log）并可选择输出到控制台。
    # 日志级别: DEBUG, INFO, WARN, ERROR, CRITICAL
    init_logging(log_file="bpst.log", level="INFO", console=True)

    # 创建一个模拟配置对象。
    # 您可以修改这些参数来改变模拟的规模和持续时间。
    config = P2PSimConfig(
        num_nodes=10,          # 网络中的节点总数
        num_clients=3,         # 上传文件的客户端数量
        sim_duration_sec=60,   # 模拟运行的总时长（秒）
        chunk_size=256,        # 文件分片大小（字节）
        file_kb=128,           # 每个客户端上传的文件大小（KB）
        base_port=59000        # 节点监听的起始端口号
    )

    # 运行主P2P模拟。
    run_p2p_simulation(config)
