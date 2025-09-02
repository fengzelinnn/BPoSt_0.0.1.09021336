"""
网络层

- 提供分片的广播（gossip）接口；
- 在 SimPy 模式下，为每个“跳数”添加固定的传播延迟.
"""
from data import FileChunk
from utils import log_msg

try:
    import simpy
except ImportError:  # 软依赖：仅仿真模式需要
    simpy = None


class Network:
    """简单网络抽象：维护节点列表并提供广播能力。"""

    def __init__(self, nodes, env: 'simpy.Environment' = None, per_hop_delay: float = 0.001):
        self.nodes = nodes
        self.env = env
        self.per_hop_delay = per_hop_delay  # 每个接收者的模拟传播延迟

    def bind_env(self, env: 'simpy.Environment'):
        """绑定 SimPy 环境以启用基于时间的过程。"""
        self.env = env
        return self

    def gossip_upload(self, chunk: FileChunk):
        """瞬时广播到所有节点（兼容 demo 的旧路径）。"""
        # 以文件为中心的日志：不记录每个分片的广播细节
        for n in self.nodes:
            n.receive_chunk(chunk)

    def gossip_upload_proc(self, chunk: FileChunk):
        """SimPy 进程：带传播延迟地向所有节点广播该分片。
        每向一个接收者传播一次，yield 一个 env.timeout 以模拟网络时延。
        """
        if self.env is None:
            # 若未绑定 env，则退化为瞬时广播
            return self.gossip_upload(chunk)
        # 以文件为中心的日志：开始传播时不逐条记录分片；在客户端层记录
        for i, n in enumerate(self.nodes):
            yield self.env.timeout(self.per_hop_delay)
            n.receive_chunk(chunk)
            # 抑制每个分片的到达日志，避免淹没
        # 抑制“完成”日志
