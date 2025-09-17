use std::collections::HashMap;

use crate::common::datastructures::BobtailProof;
use crate::utils::sha256_hex;

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
        let mut best_hash = String::new();
        let mut best_nonce = None;
        for nonce in 0..max_nonce {
            let h = sha256_hex(
                format!(
                    "bobtail|{}|{}|{}|{}",
                    seed, storage_root, self.node_id, nonce
                )
                .as_bytes(),
            );
            if best_hash.is_empty() || h < best_hash {
                best_hash = h;
                best_nonce = Some(nonce);
            }
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
