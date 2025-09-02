import random
import time
import asyncio

from blockchain import Blockchain
from client import Client, verify_final
from coordinator import RoundCoordinator
from network import Network
from server import ServerNode
from sim import run_simulation, SimConfig

"""
Two entrypoints:
- demo(): small sequential prototype for quick check.
- asyncio simulation: large-scale concurrent run with 100 users and 1000 storage nodes.
"""


def demo():
    print("Bootstrapping demo network...")
    # Initialize client and file
    client = Client("alice", chunk_size=64)
    file_bytes = ("This is a demo file for dPDP + Bobtail + Folding Scheme. "
                  "We will chunk this data and simulate proofs over several rounds. ").encode()
    chunks = client.dpdp_setup(file_bytes)

    # Create network with server nodes
    nodes = [ServerNode(f"node-{i}", store_prob=0.75) for i in range(4)]
    network = Network(nodes)

    # Client gossips upload
    client.gossip_upload(network)

    # Run a few rounds
    chain = Blockchain()
    coord = RoundCoordinator(network, chain, challenge_size=5, bobtail_k=3)
    rounds = 3
    for r in range(1, rounds + 1):
        blk = coord.run_round(height=r, client=client)
        print(
            f"Round {r} -> Leader: {blk.leader_id}, AccHash: {blk.accum_proof_hash[:16]}..., BlockHash: {blk.header_hash()[:16]}...")
        time.sleep(0.1)

    # On-demand proof request by client against a random node
    seed = chain.last_hash()
    indices = coord.select_indices(num_chunks=len(chunks), seed=seed)
    node = random.choice(nodes)
    proof_hash, per_idx = client.request_proof(node, indices, round_salt=seed)
    print(
        f"On-demand proof from {node.node_id} for indices {indices}: {proof_hash[:16]}... (storage_root {node.storage.storage_root()[:16]}...)")

    # Final verification: client checks only the final folded proof accumulator against last block
    ok = verify_final(chain)
    print(f"Final folded proof verification: {'SUCCESS' if ok else 'FAIL'}")


async def run_async_simulation():
    # Defaults already 100 users & 1000 nodes; keep as-is
    cfg = SimConfig()
    await run_simulation(cfg)


if __name__ == "__main__":
    # By default run the concurrent simulation. Comment to run small demo.
    asyncio.run(run_async_simulation())
