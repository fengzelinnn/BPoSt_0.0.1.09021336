import random
import time

from blockchain import Blockchain
from client import Client, verify_final
from coordinator import RoundCoordinator
from network import Network
from server import ServerNode
from sim import run_simulation, SimConfig
from utils import log_msg, init_logging

"""
入口脚本

- demo(): 小型顺序原型演示（单用户、少量节点、少轮次），便于快速检查流程；
- run_simpy_simulation(): 默认运行的 SimPy 仿真（可配置用户与节点规模）。
"""


def demo():
    """运行一个最小演示：上传文件 -> 多轮证明与出块 -> 按需证明 -> 最终验证。"""
    log_msg("INFO", "SYSTEM", None, "Bootstrapping demo network...")
    # 初始化客户端与文件
    client = Client("alice", chunk_size=64)
    file_bytes = ("This is a demo file for dPDP + Bobtail + Folding Scheme. "
                  "We will chunk this data and simulate proofs over several rounds. ").encode()
    chunks = client.dpdp_setup(file_bytes)

    # 创建网络与存储节点
    nodes = [ServerNode(f"node-{i}", store_prob=0.75) for i in range(4)]
    network = Network(nodes)

    # 广播上传
    client.gossip_upload(network)

    # 执行若干轮
    chain = Blockchain()
    coord = RoundCoordinator(network, chain, challenge_size=5, bobtail_k=3)
    rounds = 3
    for r in range(1, rounds + 1):
        blk = coord.run_round(height=r, client=client)
        log_msg("INFO", "SYSTEM", None,
                f"Round {r} -> Leader: {blk.leader_id}, AccHash: {blk.accum_proof_hash[:16]}..., BlockHash: {blk.header_hash()[:16]}...")
        time.sleep(0.1)

    # 客户端按需向随机节点请求一次证明
    seed = chain.last_hash()
    indices = coord.select_indices(num_chunks=len(chunks), seed=seed)
    node = random.choice(nodes)
    proof_hash, per_idx = client.request_proof(node, indices, round_salt=seed)
    log_msg("INFO", "VERIFY", node.node_id,
            f"On-demand proof for indices {indices}: {proof_hash[:16]}... (storage_root {node.storage.storage_root()[:16]}...)")

    # 最终验证：仅检查折叠累加器的简洁证明
    ok = verify_final(chain)
    log_msg("INFO", "VERIFY", None, f"Final folded proof verification: {'SUCCESS' if ok else 'FAIL'}")


# SimPy-based simulation entry (synchronous)

def run_simpy_simulation():
    """运行默认仿真：使用 SimConfig 的参数在 SimPy 环境中执行。"""
    cfg = SimConfig()
    run_simulation(cfg)


if __name__ == "__main__":
    # 初始化日志到文件（默认 bpst.log），如需同时在控制台输出可设置 console=True
    init_logging(log_file="bpst.log", level="DEBUG", console=True)
    # 默认运行 SimPy 仿真；如需运行小型 demo()，请注释下一行并调用 demo()
    run_simpy_simulation()
