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
    def __init__(self,
                 num_users: int = 100,
                 num_nodes: int = 1000,
                 user_arrival_window: float = 2.0,
                 rounds: int = 200,
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
    # Pseudo-random long string bytes
    rng = random.Random()
    return bytes(rng.getrandbits(8) for _ in range(n))


def user_proc(env: simpy.Environment, user_id: int, network: Network, clients: List[Client], cfg: SimConfig):
    # Random arrival within a window
    delay = random.random() * cfg.user_arrival_window
    yield env.timeout(delay)
    cid = f"user-{user_id}"
    client = Client(cid, chunk_size=cfg.chunk_size)
    size_kb = random.randint(cfg.file_kb_min, cfg.file_kb_max)
    file_bytes = _random_bytes(size_kb * 1024)
    chunks = client.dpdp_setup(file_bytes)
    log_msg("INFO", "USER", cid, f"[t={env.now}] Prepared file len={len(file_bytes)} bytes -> chunks={len(chunks)}; gossip upload")
    # Simulated gossip upload
    yield env.process(client.gossip_upload_proc(env, network))
    clients.append(client)
    log_msg("INFO", "USER", cid, f"[t={env.now}] Upload complete; file_id={client.file_id}")


def coordinator_proc(env: simpy.Environment, network: Network, chain: Blockchain, clients: List[Client], cfg: SimConfig):
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
        yield env.timeout(cfg.round_interval)
    log_msg("INFO", "SYSTEM", None, f"[t={env.now}] Coordinator finished scheduled rounds")


def run_simulation(cfg: SimConfig = None):
    if cfg is None:
        cfg = SimConfig()
    random.seed(cfg.seed)
    env = simpy.Environment()
    # Build network with storage nodes, bind env
    nodes = [ServerNode(f"node-{i}", store_prob=random.uniform(0.6, 0.95)).bind_env(env) for i in range(cfg.num_nodes)]
    network = Network(nodes, env=env, per_hop_delay=cfg.round_interval/100.0)
    chain = Blockchain()
    clients: List[Client] = []

    # Spawn processes
    for i in range(cfg.num_users):
        env.process(user_proc(env, i, network, clients, cfg))
    env.process(coordinator_proc(env, network, chain, clients, cfg))

    # Run the environment until coordinator finishes height==rounds
    env.run()
    log_msg("INFO", "SYSTEM", None, f"[t={env.now}] Simulation done. Blocks={len(chain.blocks)} lastHash={chain.last_hash()[:16]}...")
