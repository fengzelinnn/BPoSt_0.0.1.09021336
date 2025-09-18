use std::collections::HashMap;

use crate::common::datastructures::BobtailProof;
use crate::utils::{cpu_poseidon_hash_hex_batch, try_gpu_poseidon_hash_hex_batch};

pub struct Miner {
    pub node_id: String,
    pub reward_address: String,
}

impl Miner {
    pub fn new(node_id: String, reward_address: String) -> Self {
        Self {
            node_id,
            reward_address,
        }
    }

    pub fn mine(
        &self,
        seed: &str,
        storage_root: &str,
        file_roots: &HashMap<String, String>,
        num_files: usize,
        max_nonce: u64,
    ) -> Vec<BobtailProof> {
        // 分批处理，优先尝试 GPU 批哈希；不可用则回退到 CPU 并行批哈希
        let mut best_hash = String::new();
        let mut best_nonce: Option<u64> = None;

        if max_nonce == 0 {
            return Vec::new();
        }

        // 选择适中的批大小，兼顾吞吐与内存占用
        let chunk_size: u64 = 65_536;
        let mut start: u64 = 0;
        while start < max_nonce {
            let end = (start + chunk_size).min(max_nonce);
            let len = (end - start) as usize;

            // 预构造一批输入字节，避免在计算阶段频繁分配
            let inputs: Vec<Vec<u8>> = (0..len)
                .map(|i| {
                    let nonce = start + i as u64;
                    format!(
                        "bobtail|{}|{}|{}|{}",
                        seed, storage_root, self.node_id, nonce
                    )
                    .into_bytes()
                })
                .collect();

            // 尝试 GPU；若返回 None 则用 CPU 并行批处理
            let hashes: Vec<String> =
                if let Some(hs) = try_gpu_poseidon_hash_hex_batch(&inputs) {
                    hs
                } else {
                    cpu_poseidon_hash_hex_batch(&inputs)
                };

            // 遍历本批结果，更新全局最优
            for (i, h) in hashes.into_iter().enumerate() {
                let nonce = start + i as u64;
                if best_hash.is_empty() || h < best_hash {
                    best_hash = h;
                    best_nonce = Some(nonce);
                }
            }

            start = end;
        }

        let Some(nonce) = best_nonce else {
            return Vec::new();
        };
        vec![BobtailProof {
            node_id: self.node_id.clone(),
            address: self.reward_address.clone(),
            root: storage_root.to_string(),
            file_roots: file_roots.clone(),
            nonce: nonce.to_string(),
            proof_hash: best_hash,
            lots: num_files.max(1).to_string(),
        }]
    }
}
