import random
from typing import List, Dict

from blockchain import Blockchain, Block
from client import Client
from folding import FoldingProof
from utils import log_msg


class RoundCoordinator:
    def __init__(self, network, chain: Blockchain, challenge_size: int, bobtail_k: int):
        self.network = network
        self.chain = chain
        self.challenge_size = challenge_size
        self.bobtail_k = bobtail_k
        self.env = None

    def bind_env(self, env):
        self.env = env
        return self

    def select_indices(self, num_chunks: int, seed: str) -> List[int]:
        rng = random.Random(int(seed, 16))
        indices = set()
        while len(indices) < min(self.challenge_size, num_chunks):
            indices.add(rng.randrange(0, num_chunks))
        return sorted(indices)

    def run_round(self, height: int, client: Client) -> Block:
        prev_hash = self.chain.last_hash()
        seed = prev_hash  # use previous block hash as randomness source
        log_msg("INFO", "SYSTEM", None, f"Round {height} begin seed={seed[:16]}... client={client.client_id}")
        # ensure all nodes finalize initial commitments/state trees
        for n in self.network.nodes:
            n.finalize_initial_commitments()
        indices = self.select_indices(num_chunks=len(client.chunks), seed=seed)
        log_msg("INFO", "SYSTEM", None, f"Challenge indices for file={client.file_id}: {indices}")
        # Each node computes a DPDP aggregate proof for selected indices on the client's file
        node_proofs: Dict[str, str] = {}
        storage_roots: Dict[str, str] = {}
        time_roots_by_node: Dict[str, Dict[str, str]] = {}
        for n in self.network.nodes:
            proof_hash, _ = n.dpdp_prove(indices, round_salt=seed, file_id=client.file_id)
            node_proofs[n.node_id] = proof_hash
            storage_roots[n.node_id] = n.storage.storage_root()
            time_roots_by_node[n.node_id] = n.storage.export_time_roots()
        log_msg("INFO", "SYSTEM", None, f"Collected proofs from {len(node_proofs)} nodes for round {height}")
        # Build this round's statement hash by combining all node proofs deterministically
        from utils import h_join
        stmt_parts = ["round", str(height), seed]
        for nid in sorted(node_proofs.keys()):
            stmt_parts.append(nid)
            stmt_parts.append(node_proofs[nid])
        round_stmt_hash = h_join(*stmt_parts)
        log_msg("DEBUG", "SYSTEM", None, f"RoundStmtHash={round_stmt_hash[:16]}...")
        # Fold all node proofs into a single folded proof for the round
        folded = FoldingProof.from_statement(round_stmt_hash)
        # Bobtail mining: each node mines a proof using its Storage State Tree root
        proof_sets = []
        for n in self.network.nodes:
            lots = max(1, n.storage.num_files())
            # Reduce mining iterations for scalability in large simulations
            max_nonce = min(256, 16 * lots)
            ps = n.mine_bobtail(seed=seed, max_nonce=max_nonce)
            proof_sets.append(ps)
        log_msg("INFO", "SYSTEM", None, f"Bobtail proofs mined: {len(proof_sets)}; selecting top-k={self.bobtail_k}")
        # Select k lowest proofs
        k = max(1, min(self.bobtail_k, len(proof_sets)))
        proof_sets.sort(key=lambda p: int(p["proof_value"]))
        selected = proof_sets[:k]
        avg = sum(int(p["proof_value"]) for p in selected) / k
        # Target difficulty t_k (prototype: high target to ensure block creation)
        t_k = (1 << 255)  # deterministic large target
        log_msg("INFO", "SYSTEM", None, f"Top-k selected avgV={int(avg)} target={t_k}")
        # Leader is node with global minimum proof V1
        leader_id = selected[0]["node_id"] if selected else (
            self.network.nodes[0].node_id if self.network.nodes else "")
        log_msg("INFO", "SYSTEM", None, f"Leader={leader_id}")
        # Collect full PoSt Storage State Trees' leaves (i.e., time roots) from the k contributing nodes
        included_trees: Dict[str, List[str]] = {}
        node_by_id = {n.node_id: n for n in self.network.nodes}
        for ps in selected:
            nid = ps["node_id"]
            leaves = node_by_id[nid].export_merkle_leaves() if nid in node_by_id else []
            included_trees[nid] = leaves
        # Compute proportional coinbase splits (inverse of proof value)
        weights = [1.0 / (int(p["proof_value"]) + 1.0) for p in selected]
        total_w = sum(weights) if weights else 1.0
        splits = {}
        for ps, w in zip(selected, weights):
            share = w / total_w
            splits[ps["node_id"]] = f"{share:.6f}"
        # Leader creates block; accum hash will be after folding with chain.acc
        accum_if_appended = self.chain.acc.fold_with(folded).acc_hash
        block = Block(
            height=height,
            prev_hash=prev_hash,
            seed=seed,
            leader_id=leader_id or "",
            accum_proof_hash=accum_if_appended,
            merkle_roots=storage_roots,
            round_proof_stmt_hash=round_stmt_hash,
            bobtail_k=k,
            bobtail_target=str(t_k),
            selected_k_proofs=selected,
            included_post_trees=included_trees,
            coinbase_splits=splits,
        )
        # Append block and update chain accumulator
        self.chain.add_block(block, folded)
        log_msg("INFO", "SYSTEM", None, f"Round {height} -> BlockHash={block.header_hash()[:16]}... AccHash={block.accum_proof_hash[:16]}...")
        return block

    def run_round_proc(self, env, height: int, client: Client, compute_delay: float = 0.002):
        """SimPy process for a consensus round: schedule per-node dpdp and mining with delays."""
        prev_hash = self.chain.last_hash()
        seed = prev_hash
        log_msg("INFO", "SYSTEM", None, f"[t={env.now}] Round {height} begin seed={seed[:16]}... client={client.client_id}")
        for n in self.network.nodes:
            n.finalize_initial_commitments()
        indices = self.select_indices(num_chunks=len(client.chunks), seed=seed)
        log_msg("INFO", "SYSTEM", None, f"[t={env.now}] Challenge indices for file={client.file_id}: {indices}")
        node_proofs: Dict[str, str] = {}
        storage_roots: Dict[str, str] = {}
        time_roots_by_node: Dict[str, Dict[str, str]] = {}
        # sequentially simulate each node's dpdp compute; could be parallelized by spawning processes
        for n in self.network.nodes:
            res_event = yield env.process(n.dpdp_prove_proc(env, indices, round_salt=seed, file_id=client.file_id, compute_delay=compute_delay))
            proof_hash, _ = res_event
            node_proofs[n.node_id] = proof_hash
            storage_roots[n.node_id] = n.storage.storage_root()
            time_roots_by_node[n.node_id] = n.storage.export_time_roots()
        from utils import h_join
        stmt_parts = ["round", str(height), seed]
        for nid in sorted(node_proofs.keys()):
            stmt_parts.append(nid)
            stmt_parts.append(node_proofs[nid])
        round_stmt_hash = h_join(*stmt_parts)
        folded = FoldingProof.from_statement(round_stmt_hash)
        proof_sets = []
        for n in self.network.nodes:
            lots = max(1, n.storage.num_files())
            max_nonce = min(256, 16 * lots)
            ps = yield env.process(n.mine_bobtail_proc(env, seed=seed, max_nonce=max_nonce, compute_per_nonce=compute_delay/16.0))
            proof_sets.append(ps)
        k = max(1, min(self.bobtail_k, len(proof_sets)))
        proof_sets.sort(key=lambda p: int(p["proof_value"]))
        selected = proof_sets[:k]
        avg = sum(int(p["proof_value"]) for p in selected) / k if k else 0
        t_k = (1 << 255)
        log_msg("INFO", "SYSTEM", None, f"[t={env.now}] Round {height} mined {len(proof_sets)} proofs; avg={int(avg)} target={t_k}")
        leader_id = selected[0]["node_id"] if selected else (self.network.nodes[0].node_id if self.network.nodes else "")
        included_trees = {}
        node_by_id = {n.node_id: n for n in self.network.nodes}
        for ps in selected:
            nid = ps["node_id"]
            leaves = node_by_id[nid].export_merkle_leaves() if nid in node_by_id else []
            included_trees[nid] = leaves
        weights = [1.0 / (int(p["proof_value"]) + 1.0) for p in selected] if selected else [1.0]
        total_w = sum(weights)
        splits = {}
        for ps, w in zip(selected, weights):
            splits[ps["node_id"]] = f"{(w/total_w):.6f}"
        accum_if_appended = self.chain.acc.fold_with(folded).acc_hash
        block = Block(
            height=height,
            prev_hash=prev_hash,
            seed=seed,
            leader_id=leader_id or "",
            accum_proof_hash=accum_if_appended,
            merkle_roots=storage_roots,
            round_proof_stmt_hash=round_stmt_hash,
            bobtail_k=k,
            bobtail_target=str(t_k),
            selected_k_proofs=selected,
            included_post_trees=included_trees,
            coinbase_splits=splits,
        )
        self.chain.add_block(block, folded)
        log_msg("INFO", "SYSTEM", None, f"[t={env.now}] Round {height} -> BlockHash={block.header_hash()[:16]}... AccHash={block.accum_proof_hash[:16]}...")
        return block
