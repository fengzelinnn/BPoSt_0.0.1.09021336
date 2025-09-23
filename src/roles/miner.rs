// 导入标准库的 HashMap 用于存储键值对
use std::collections::HashMap;

// 导入项目内的数据结构 BobtailProof
use crate::common::datastructures::BobtailProof;
// 导入项目内的工具函数，包括 CPU 和 GPU 上的 Poseidon 哈希实现
use crate::utils::{cpu_poseidon_hash_hex_batch, try_gpu_poseidon_hash_hex_batch};

/// Miner 结构体定义了矿工的角色
/// 矿工负责通过“挖矿”来创建 Bobtail 证明，这是参与共识的关键步骤
#[derive(Clone)]
pub struct Miner {
    // 矿工所属节点的 ID
    pub node_id: String,
    // 接收挖矿奖励的地址
    pub reward_address: String,
}

impl Miner {
    /// 创建一个新的 Miner 实例
    pub fn new(node_id: String, reward_address: String) -> Self {
        Self {
            node_id,
            reward_address,
        }
    }

    /// 执行挖矿操作，尝试找到一个符合条件的 Bobtail 证明
    /// 挖矿的本质是寻找一个 nonce（随机数），使得组合了各种信息后的哈希值最小。
    ///
    /// 为了体现“存储越多、机会越多”的机制，此处会针对节点持有的每个文件状态树根
    /// 生成一套独立的挖矿种子 `prev_hash + file_root + nonce`，从而让拥有更多文件的节点
    /// 能够在同样的窗口内尝试更多的哈希组合。
    pub fn mine(
        &self,
        seed: &str,         // 挖矿种子，通常来自前一个区块的哈希，确保不可预测性
        storage_root: &str, // 矿工存储根哈希，证明其存储状态
        file_roots: &HashMap<String, String>, // 存储的各个文件的根哈希
        num_files: usize,   // 存储的文件数量
        max_nonce: u64,     // 要尝试的最大 nonce 值，限制了单次挖矿的计算量
    ) -> Vec<BobtailProof> {
        self.mine_window(seed, storage_root, file_roots, num_files, 0, max_nonce)
            .into_iter()
            .collect()
    }

    /// 在指定的 nonce 范围内执行一次挖矿搜索
    /// 返回在 [start_nonce, start_nonce + window_size) 区间内找到的最佳证明
    pub fn mine_window(
        &self,
        seed: &str,
        storage_root: &str,
        file_roots: &HashMap<String, String>,
        num_files: usize,
        start_nonce: u64,
        window_size: u64,
    ) -> Option<BobtailProof> {
        if window_size == 0 {
            return None;
        }

        let mut best_hash: Option<String> = None;
        let mut best_nonce: Option<u64> = None;
        let mut best_root_idx: Option<usize> = None;

        // 避免在计算 end_nonce 时发生溢出
        let end_nonce = start_nonce.saturating_add(window_size);
        if end_nonce == start_nonce {
            return None;
        }

        let candidate_roots: Vec<String> = if file_roots.is_empty() {
            // 当文件根为空时退化为使用整体存储根，保持兼容性
            vec![storage_root.to_string()]
        } else {
            file_roots.values().cloned().collect()
        };

        if candidate_roots.is_empty() {
            return None;
        }

        let chunk_size: u64 = 65_536;
        let mut start = start_nonce;
        while start < end_nonce {
            let end = end_nonce.min(start.saturating_add(chunk_size));
            let len = (end - start) as usize;
            if len == 0 {
                break;
            }

            let mut inputs: Vec<Vec<u8>> = Vec::with_capacity(len * candidate_roots.len());
            let mut metadata: Vec<(usize, u64)> = Vec::with_capacity(len * candidate_roots.len());
            for (root_idx, file_root) in candidate_roots.iter().enumerate() {
                for offset in 0..len {
                    let nonce = start + offset as u64;
                    inputs.push(
                        format!("bobtail|{}|{}|{}|{}", seed, file_root, self.node_id, nonce)
                            .into_bytes(),
                    );
                    metadata.push((root_idx, nonce));
                }
            }

            let hashes: Vec<String> = if let Some(hs) = try_gpu_poseidon_hash_hex_batch(&inputs) {
                hs
            } else {
                cpu_poseidon_hash_hex_batch(&inputs)
            };

            for ((root_idx, nonce), hash) in metadata.into_iter().zip(hashes.into_iter()) {
                if best_hash.as_ref().map_or(true, |current| hash < *current) {
                    best_root_idx = Some(root_idx);
                    best_nonce = Some(nonce);
                    best_hash = Some(hash);
                }
            }

            if end == u64::MAX {
                break;
            }
            start = end;
        }

        match (best_hash, best_nonce, best_root_idx) {
            (Some(hash), Some(nonce), Some(root_idx)) => Some(BobtailProof {
                node_id: self.node_id.clone(),
                address: self.reward_address.clone(),
                root: candidate_roots[root_idx].clone(),
                file_roots: file_roots.clone(),
                nonce: nonce.to_string(),
                proof_hash: hash,
                lots: num_files.max(1).to_string(),
            }),
            _ => None,
        }
    }
}
