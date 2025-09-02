"""
共识轮次协调器

- 依据上一块哈希作为公共随机种子，生成本轮 dPDP 挑战索引；
- 收集各存储节点对指定文件的聚合证明（dPDP），并折叠为本轮语句；
- 触发 Bobtail 挖矿：基于各节点的存储状态树根，选择全网最优的前 k 个 PoW 结果；
- 选出 Leader、汇总 Provider 的状态树叶子与奖励分配，构造新区块并上链；
- 同步维护折叠证明的全局累加器（链级）。
"""
import random
from typing import List, Dict

from blockchain import Blockchain, Block
from client import Client
from folding import FoldingProof
from utils import log_msg


class RoundCoordinator:
    """负责单轮共识的组织与执行。

    职责：
    - 生成挑战索引（与文件块数量与随机种子有关）；
    - 驱动各节点产生 dPDP 聚合证明并折叠；
    - 执行 Bobtail 选择（按 proof_value 升序取前 k 名，Leader 为最小值提交者）；
    - 打包区块并更新链上折叠累加器。
    """

    def __init__(self, network, chain: Blockchain, challenge_size: int, bobtail_k: int):
        self.network = network
        self.chain = chain
        self.challenge_size = challenge_size
        self.bobtail_k = bobtail_k
        self.env = None

    def bind_env(self, env):
        """绑定 SimPy 环境。返回 self 以便链式调用。"""
        self.env = env
        return self

    def select_indices(self, num_chunks: int, seed: str) -> List[int]:
        """根据公共随机种子与文件块数量，生成本轮挑战的索引集合。
        采用确定性伪随机过程，确保所有参与者可公开复现同一挑战。
        """
        rng = random.Random(int(seed, 16))
        indices = set()
        while len(indices) < min(self.challenge_size, num_chunks):
            indices.add(rng.randrange(0, num_chunks))
        return sorted(indices)

    def run_round(self, height: int, client: Client) -> Block:
        """顺序版本：执行一轮完整的共识流程，返回生成的区块。"""
        prev_hash = self.chain.last_hash()
        seed = prev_hash  # 以上一块哈希作为随机源
        log_msg("INFO", "SYSTEM", None, f"Round {height} begin seed={seed[:16]}... client={client.client_id}")
        # 确保所有节点完成初始承诺/状态树构建
        for n in self.network.nodes:
            n.finalize_initial_commitments()
        indices = self.select_indices(num_chunks=len(client.chunks), seed=seed)
        log_msg("INFO", "SYSTEM", None, f"Challenge seed={seed[:12]}... file={client.file_id} indices={indices}")
        # 收集每个节点针对该文件的 dPDP 聚合证明
        node_proofs: Dict[str, str] = {}
        storage_roots: Dict[str, str] = {}
        time_roots_by_node: Dict[str, Dict[str, str]] = {}
        for n in self.network.nodes:
            proof_hash, _ = n.dpdp_prove(indices, round_salt=seed, file_id=client.file_id)
            node_proofs[n.node_id] = proof_hash
            storage_roots[n.node_id] = n.storage.storage_root()
            time_roots_by_node[n.node_id] = n.storage.export_time_roots()
        log_msg("INFO", "SYSTEM", None, f"Collected proofs from {len(node_proofs)} nodes for round {height}")
        # 将所有节点的证明按节点ID排序后拼接，形成本轮语句哈希
        from utils import h_join
        stmt_parts = ["round", str(height), seed]
        for nid in sorted(node_proofs.keys()):
            stmt_parts.append(nid)
            stmt_parts.append(node_proofs[nid])
        round_stmt_hash = h_join(*stmt_parts)
        log_msg("INFO", "VERIFY", None, f"Fold round file={client.file_id} stmt={round_stmt_hash[:16]}...")
        # 本轮折叠证明（常大小）
        folded = FoldingProof.from_statement(round_stmt_hash)
        # Bobtail 挖矿：每个节点以存储状态树根为承诺，搜索最小哈希值
        proof_sets = []
        for n in self.network.nodes:
            lots = max(1, n.storage.num_files())
            # 在大规模仿真中限制 nonce 搜索上限以控制耗时
            max_nonce = min(256, 16 * lots)
            ps = n.mine_bobtail(seed=seed, max_nonce=max_nonce)
            proof_sets.append(ps)
        log_msg("INFO", "SYSTEM", None, f"Bobtail proofs mined: {len(proof_sets)}; selecting top-k={self.bobtail_k}")
        # 选择全网最小的前 k 个 proof_value
        k = max(1, min(self.bobtail_k, len(proof_sets)))
        proof_sets.sort(key=lambda p: int(p["proof_value"]))
        selected = proof_sets[:k]
        avg = sum(int(p["proof_value"]) for p in selected) / k
        # 难度阈值 t_k（原型中设为较大常数，保证容易出块）
        t_k = (1 << 255)  # 确定性的大目标
        log_msg("INFO", "SYSTEM", None, f"Top-k selected avgV={int(avg)} target={t_k}")
        # Leader 为最小 proof_value 的提交者
        leader_id = selected[0]["node_id"] if selected else (
            self.network.nodes[0].node_id if self.network.nodes else "")
        log_msg("INFO", "SYSTEM", None, f"Leader={leader_id}")
        # 收集被选 k 个节点的存储状态树叶子（即其所有时间状态树根）
        included_trees: Dict[str, List[str]] = {}
        node_by_id = {n.node_id: n for n in self.network.nodes}
        for ps in selected:
            nid = ps["node_id"]
            leaves = node_by_id[nid].export_merkle_leaves() if nid in node_by_id else []
            included_trees[nid] = leaves
        # 计算奖励分配：按 proof_value 的倒数归一化
        weights = [1.0 / (int(p["proof_value"]) + 1.0) for p in selected]
        total_w = sum(weights) if weights else 1.0
        splits = {}
        for ps, w in zip(selected, weights):
            share = w / total_w
            splits[ps["node_id"]] = f"{share:.6f}"
        # 构造区块：accum_proof_hash 为链上累加器与本轮折叠融合后的预览
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
        # 上链并更新全局折叠累加器
        self.chain.add_block(block, folded)
        log_msg("INFO", "SYSTEM", None, f"Round {height} -> BlockHash={block.header_hash()[:16]}... AccHash={block.accum_proof_hash[:16]}...")
        return block

    def run_round_proc(self, env, height: int, client: Client, compute_delay: float = 0.002):
        """SimPy 进程版本：带有计算/网络延迟的单轮共识流程。"""
        prev_hash = self.chain.last_hash()
        seed = prev_hash
        log_msg("INFO", "SYSTEM", None, f"[t={env.now}] Round {height} begin seed={seed[:16]}... client={client.client_id}")
        for n in self.network.nodes:
            n.finalize_initial_commitments()
        indices = self.select_indices(num_chunks=len(client.chunks), seed=seed)
        log_msg("INFO", "SYSTEM", None, f"[t={env.now}] Challenge seed={seed[:12]}... file={client.file_id} indices={indices}")
        node_proofs: Dict[str, str] = {}
        storage_roots: Dict[str, str] = {}
        time_roots_by_node: Dict[str, Dict[str, str]] = {}
        # 依次模拟每个节点的 dPDP 计算，可并发为多个进程
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
        log_msg("INFO", "VERIFY", None, f"[t={env.now}] Fold round file={client.file_id} stmt={round_stmt_hash[:16]}...")
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
        # 奖励分配：按 proof_value 的倒数归一化
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
