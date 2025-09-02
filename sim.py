import asyncio
import random
from typing import List

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


async def user_task(user_id: int, network: Network, clients: List[Client], cfg: SimConfig):
    # Random arrival within a window
    delay = random.random() * cfg.user_arrival_window
    await asyncio.sleep(delay)
    cid = f"user-{user_id}"
    client = Client(cid, chunk_size=cfg.chunk_size)
    size_kb = random.randint(cfg.file_kb_min, cfg.file_kb_max)
    file_bytes = _random_bytes(size_kb * 1024)
    chunks = client.dpdp_setup(file_bytes)
    log_msg("INFO", "USER", cid, f"Prepared file len={len(file_bytes)} bytes -> chunks={len(chunks)}; gossip upload")
    client.gossip_upload(network)
    clients.append(client)
    log_msg("INFO", "USER", cid, f"Upload complete; file_id={client.file_id}")


async def coordinator_task(network: Network, chain: Blockchain, clients: List[Client], cfg: SimConfig):
    coord = RoundCoordinator(network, chain, challenge_size=cfg.challenge_size, bobtail_k=cfg.bobtail_k)
    height = 1
    for rnd in range(cfg.rounds):
        # Choose a subset of available clients this round
        ready = clients[:]
        if not ready:
            log_msg("INFO", "SYSTEM", None, "No clients ready yet; waiting...")
            await asyncio.sleep(cfg.round_interval)
            continue
        m = min(cfg.clients_per_round, len(ready))
        selected = random.sample(ready, m)
        log_msg("INFO", "SYSTEM", None, f"System round {rnd+1}: processing {m} clients -> {[c.client_id for c in selected]}")
        for c in selected:
            blk = coord.run_round(height=height, client=c)
            log_msg("INFO", "SYSTEM", None,
                    f"Height {height} committed; leader={blk.leader_id} block={blk.header_hash()[:16]}... acc={blk.accum_proof_hash[:16]}...")
            height += 1
        await asyncio.sleep(cfg.round_interval)
    log_msg("INFO", "SYSTEM", None, "Coordinator finished scheduled rounds")


async def run_simulation(cfg: SimConfig = None):
    if cfg is None:
        cfg = SimConfig()
    random.seed(cfg.seed)
    # Build network with storage nodes
    nodes = [ServerNode(f"node-{i}", store_prob=random.uniform(0.6, 0.95)) for i in range(cfg.num_nodes)]
    network = Network(nodes)
    chain = Blockchain()
    clients: List[Client] = []

    # Launch tasks
    user_tasks = [asyncio.create_task(user_task(i, network, clients, cfg)) for i in range(cfg.num_users)]
    coord_task = asyncio.create_task(coordinator_task(network, chain, clients, cfg))

    await asyncio.gather(*user_tasks)
    # Users done; let coordinator finish remaining rounds
    await coord_task
    log_msg("INFO", "SYSTEM", None, f"Simulation done. Blocks={len(chain.blocks)} lastHash={chain.last_hash()[:16]}...")
