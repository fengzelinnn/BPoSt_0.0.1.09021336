"""
SimPy 仿真入口

- 随机生成用户到达与文件大小，执行 dPDP 预处理并经网络广播；
- 周期性触发共识轮次（RoundCoordinator），执行 dPDP -> Folding -> Bobtail -> 出块；
- 输出结构化日志（写入 bpst.log）.
"""
import random
from typing import List

import simpy
from blockchain import Blockchain
from client import Client
from coordinator import RoundCoordinator
from network import Network
from server import ServerNode
from utils import log_msg


class SimConfig:
    """仿真配置参数集合。"""

    def __init__(self,
                 num_users: int = 100,
                 num_nodes: int = 1000,
                 user_arrival_window: float = 2.0,
                 rounds: int = 20,
                 clients_per_round: int = 5,
                 chunk_size: int = 4096,
                 file_kb_min: int = 64,
                 file_kb_max: int = 128,
                 challenge_size: int = 5,
                 bobtail_k: int = 7,
                 seed: int = 42,
                 round_interval: float = 0.25):
        self.num_users = num_users
        self.num_nodes = num_nodes
        self.user_arrival_window = user_arrival_window
        self.rounds = rounds
        self.clients_per_round = clients_per_round
        self.chunk_size = chunk_size
        self.file_kb_min = file_kb_min
        self.file_kb_max = file_kb_max
        self.challenge_size = challenge_size
        self.bobtail_k = bobtail_k
        self.seed = seed
        self.round_interval = round_interval


def _random_bytes(n: int) -> bytes:
    """生成 n 字节的伪随机数据（用于模拟文件内容）。"""
    rng = random.Random()
    return bytes(rng.getrandbits(8) for _ in range(n))


def user_proc(env: simpy.Environment, user_id: int, network: Network, clients: List[Client], cfg: SimConfig):
    """用户进程：随机到达 -> 生成文件 -> dPDP 预处理 -> 通过网络广播。"""
    # 随机到达时间窗口
    delay = random.random() * cfg.user_arrival_window
    yield env.timeout(delay)
    cid = f"user-{user_id}"
    client = Client(cid, chunk_size=cfg.chunk_size)
    size_kb = random.randint(cfg.file_kb_min, cfg.file_kb_max)
    file_bytes = _random_bytes(size_kb * 1024)
    chunks = client.dpdp_setup(file_bytes)
    log_msg("INFO", "USER", cid, f"[t={env.now}] Prepared file len={len(file_bytes)} bytes -> chunks={len(chunks)}; gossip upload")
    # 模拟网络广播
    yield env.process(client.gossip_upload_proc(env, network))
    clients.append(client)
    log_msg("INFO", "USER", cid, f"[t={env.now}] Upload complete; file_id={client.file_id}")


def coordinator_proc(env: simpy.Environment, network: Network, chain: Blockchain, clients: List[Client], cfg: SimConfig):
    """协调器进程：周期性选择若干客户端，驱动单轮共识并出块。"""
    coord = RoundCoordinator(network, chain, challenge_size=cfg.challenge_size, bobtail_k=cfg.bobtail_k).bind_env(env)
    height = 1
    while height <= cfg.rounds:
        ready = clients[:]
        if not ready:
            log_msg("INFO", "SYSTEM", None, f"[t={env.now}] No clients ready yet; waiting...")
            yield env.timeout(cfg.round_interval)
            continue
        m = min(cfg.clients_per_round, len(ready))
        selected = random.sample(ready, m)
        log_msg("INFO", "SYSTEM", None, f"[t={env.now}] System processing {m} clients -> {[c.client_id for c in selected]}")
        for c in selected:
            blk = yield from coord.run_round_proc(env, height=height, client=c, compute_delay=cfg.round_interval/10.0)
            log_msg("INFO", "SYSTEM", None,
                    f"[t={env.now}] Height {height} committed; leader={blk.leader_id} block={blk.header_hash()[:16]}... acc={blk.accum_proof_hash[:16]}...")
            height += 1
        # 两个批次之间留出固定间隔
        yield env.timeout(cfg.round_interval)
    log_msg("INFO", "SYSTEM", None, f"[t={env.now}] Coordinator finished scheduled rounds")


def run_simulation(cfg: SimConfig = None):
    """运行完整仿真：生成用户/节点，绑定网络与环境，直到完成既定轮次。"""
    if cfg is None:
        cfg = SimConfig()
    random.seed(cfg.seed)
    env = simpy.Environment()
    # 构建存储节点并绑定环境
    nodes = [ServerNode(f"node-{i}", store_prob=random.uniform(0.6, 0.95)).bind_env(env) for i in range(cfg.num_nodes)]
    network = Network(nodes, env=env, per_hop_delay=cfg.round_interval/100.0)
    chain = Blockchain()
    clients: List[Client] = []

    # 启动用户与协调器进程
    for i in range(cfg.num_users):
        env.process(user_proc(env, i, network, clients, cfg))
    env.process(coordinator_proc(env, network, chain, clients, cfg))

    # 运行环境直到协调器完成指定高度
    env.run()
    log_msg("INFO", "SYSTEM", None, f"[t={env.now}] Simulation done. Blocks={len(chain.blocks)} lastHash={chain.last_hash()[:16]}...")
