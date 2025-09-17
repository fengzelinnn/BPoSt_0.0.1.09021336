use std::collections::HashMap;

use num_bigint::BigUint;
use parking_lot::Mutex;

use crate::common::datastructures::{DPDPProof, DPDPTags, FileChunk};
use crate::storage::state::ServerStorage;
use crate::utils::{h_join, sha256_hex};

struct StorageManagerInner {
    chunk_size: usize,
    max_storage: usize,
    used_space: usize,
    storage: ServerStorage,
    files: HashMap<String, HashMap<usize, (Vec<u8>, Vec<u8>)>>,
    file_pk_beta: HashMap<String, Vec<u8>>,
}

pub struct StorageManager {
    node_id: String,
    inner: Mutex<StorageManagerInner>,
}

impl StorageManager {
    pub fn new(node_id: String, chunk_size: usize, max_storage: usize) -> Self {
        let inner = StorageManagerInner {
            chunk_size,
            max_storage,
            used_space: 0,
            storage: ServerStorage::default(),
            files: HashMap::new(),
            file_pk_beta: HashMap::new(),
        };
        Self {
            node_id,
            inner: Mutex::new(inner),
        }
    }

    pub fn can_store(&self, size: usize) -> bool {
        let inner = self.inner.lock();
        inner.used_space + size <= inner.max_storage
    }

    pub fn receive_chunk(&self, chunk: &FileChunk) -> bool {
        let mut inner = self.inner.lock();
        if inner.used_space + inner.chunk_size > inner.max_storage {
            crate::utils::log_msg(
                "WARN",
                "STORE",
                Some(self.node_id.clone()),
                &format!(
                    "拒绝存储文件块 {}[{}]：存储空间不足。",
                    chunk.file_id, chunk.index
                ),
            );
            return false;
        }
        inner
            .files
            .entry(chunk.file_id.clone())
            .or_default()
            .insert(chunk.index, (chunk.data.clone(), chunk.tag.clone()));
        let commitment = h_join(["commit", &hex::encode(&chunk.tag), &sha256_hex(&chunk.data)]);
        inner
            .storage
            .add_chunk_commitment(&chunk.file_id, chunk.index, commitment);
        inner.used_space += inner.chunk_size;
        true
    }

    pub fn finalize_commitments(&self) {
        let mut inner = self.inner.lock();
        inner.storage.build_state();
        crate::utils::log_msg(
            "INFO",
            "COMMIT",
            Some(self.node_id.clone()),
            "已为接收的文件块构建状态树",
        );
    }

    pub fn get_storage_root(&self) -> String {
        let inner = self.inner.lock();
        inner.storage.storage_root()
    }

    pub fn get_file_roots(&self) -> HashMap<String, String> {
        let inner = self.inner.lock();
        inner
            .storage
            .storage_tree
            .as_ref()
            .map(|tree| tree.file_roots.clone())
            .unwrap_or_default()
    }

    pub fn get_num_files(&self) -> usize {
        let inner = self.inner.lock();
        inner.storage.num_files()
    }

    pub fn list_file_ids(&self) -> Vec<String> {
        let inner = self.inner.lock();
        inner.files.keys().cloned().collect()
    }

    pub fn get_file_data_for_proof(&self, file_id: &str) -> (HashMap<usize, Vec<u8>>, DPDPTags) {
        let inner = self.inner.lock();
        let file_data = inner
            .files
            .get(file_id)
            .cloned()
            .unwrap_or_else(|| panic!("文件 {} 未找到", file_id));
        let mut chunks = HashMap::new();
        let mut tags = Vec::new();
        let mut sorted: Vec<(usize, (Vec<u8>, Vec<u8>))> = file_data.into_iter().collect();
        sorted.sort_by_key(|(idx, _)| *idx);
        for (idx, (data, tag)) in sorted {
            chunks.insert(idx, data);
            tags.push(tag);
        }
        (chunks, DPDPTags { tags })
    }

    pub fn set_file_pk_beta(&self, file_id: &str, pk_beta: Vec<u8>) {
        let mut inner = self.inner.lock();
        inner.file_pk_beta.insert(file_id.to_string(), pk_beta);
    }

    pub fn get_file_pk_beta(&self, file_id: &str) -> Option<Vec<u8>> {
        let inner = self.inner.lock();
        inner.file_pk_beta.get(file_id).cloned()
    }

    pub fn update_state_after_proof(
        &self,
        file_id: &str,
        indices: &[usize],
        proof: &DPDPProof,
        round_salt: &str,
    ) {
        let mut inner = self.inner.lock();
        let proof_hash = sha256_hex(&proof.sigma);
        if let Some(tst) = inner.storage.time_trees.get(file_id) {
            let updates: Vec<(usize, String)> = indices
                .iter()
                .map(|idx| {
                    let prev_leaf = tst
                        .leaves
                        .get(idx)
                        .cloned()
                        .unwrap_or_else(|| h_join(["missing", &idx.to_string()]));
                    let new_leaf = h_join(["tleaf", &prev_leaf, &proof_hash, round_salt]);
                    (*idx, new_leaf)
                })
                .collect();
            for (idx, new_leaf) in updates {
                inner.storage.add_chunk_commitment(file_id, idx, new_leaf);
            }
            inner.storage.build_state();
            crate::utils::log_msg(
                "DEBUG",
                "PoSt",
                Some(self.node_id.clone()),
                &format!(
                    "使用证明哈希 {} 更新了文件 {} 的时间状态。",
                    &proof_hash[..16],
                    file_id
                ),
            );
        }
    }

    pub fn update_state_after_contributions(
        &self,
        file_id: &str,
        contributions: &[(usize, BigUint, Vec<u8>)],
        round_salt: &str,
    ) {
        let mut inner = self.inner.lock();
        if let Some(tst) = inner.storage.time_trees.get(file_id) {
            let updates: Vec<(usize, String)> = contributions
                .iter()
                .map(|(idx, mu_i, sigma_bytes)| {
                    let prev_leaf = tst
                        .leaves
                        .get(idx)
                        .cloned()
                        .unwrap_or_else(|| h_join(["missing", &idx.to_string()]));
                    let sigma_hex = hex::encode(sigma_bytes);
                    let new_leaf = h_join([
                        "tleaf",
                        &prev_leaf,
                        "mu",
                        &mu_i.to_string(),
                        "sigma",
                        &sigma_hex,
                        round_salt,
                    ]);
                    (*idx, new_leaf)
                })
                .collect();
            for (idx, new_leaf) in updates {
                inner.storage.add_chunk_commitment(file_id, idx, new_leaf);
            }
            inner.storage.build_state();
            crate::utils::log_msg(
                "DEBUG",
                "PoSt",
                Some(self.node_id.clone()),
                &format!(
                    "使用未聚合对更新了文件 {} 的时间状态（{} 个分片）。",
                    file_id,
                    contributions.len()
                ),
            );
        }
    }
}
