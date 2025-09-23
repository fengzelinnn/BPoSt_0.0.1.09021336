use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use ark_bn254::{G1Projective, G2Projective};
use ark_ec::PrimeGroup;
use num_bigint::BigUint;
use parking_lot::Mutex;

use crate::common::datastructures::{Block, DPDPParams, DPDPProof, DPDPTags, FileChunk};
use crate::crypto::deserialize_g2;
use crate::crypto::folding::{
    block_validation_relaxed_r1cs, dpdp_verification_relaxed_r1cs, fr_to_padded_hex,
    state_update_relaxed_r1cs, NovaFinalProof, NovaFoldingCycle, NovaFoldingError, NovaRoundResult,
};
use crate::storage::state::ServerStorage;
use crate::utils::{h_join, sha256_hex};
use serde_json::Value as JsonValue;

struct StorageManagerInner {
    chunk_size: usize,
    max_storage: usize,
    used_space: usize,
    storage: ServerStorage,
    files: HashMap<String, HashMap<usize, (Vec<u8>, Vec<u8>)>>,
    file_expected_chunks: HashMap<String, usize>,
    file_pk_beta: HashMap<String, Vec<u8>>,
    file_cycles: HashMap<String, FileCycleState>,
    file_owner_contacts: HashMap<String, SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct StoredRoundRecord {
    pub round: usize,
    pub challenge: Vec<(usize, BigUint)>,
    pub proof: DPDPProof,
    pub accumulator: String,
}

#[derive(Debug, Clone)]
pub struct FinalFoldArtifact {
    pub accumulator: String,
    pub steps: usize,
    pub compressed_snark: String,
    pub verifier_key: String,
}

#[derive(Debug, Clone)]
pub enum FileDataError {
    NotFound,
    Expired,
    Incomplete { missing_indices: Vec<usize> },
}

struct FileCycleState {
    storage_period: usize,
    challenge_size: usize,
    nova: NovaFoldingCycle,
    pending_rounds: VecDeque<StoredRoundRecord>,
    final_artifact: Option<FinalFoldArtifact>,
    final_sent: bool,
    released: bool,
}

impl FileCycleState {
    fn new(storage_period: usize, challenge_size: usize) -> Self {
        Self {
            storage_period,
            challenge_size,
            nova: NovaFoldingCycle::new(storage_period),
            pending_rounds: VecDeque::new(),
            final_artifact: None,
            final_sent: false,
            released: false,
        }
    }

    fn record_round(
        &mut self,
        result: NovaRoundResult,
        challenge: Vec<(usize, BigUint)>,
        proof: DPDPProof,
    ) {
        self.pending_rounds.push_back(StoredRoundRecord {
            round: result.step_index,
            challenge,
            proof,
            accumulator: fr_to_padded_hex(&result.accumulator),
        });
    }

    fn set_final_artifact(&mut self, proof: NovaFinalProof) {
        self.final_artifact = Some(FinalFoldArtifact {
            accumulator: fr_to_padded_hex(&proof.accumulator),
            steps: proof.steps,
            compressed_snark: hex::encode(&proof.compressed_snark),
            verifier_key: hex::encode(&proof.verifier_key),
        });
        self.final_sent = false;
    }

    fn is_expired(&self) -> bool {
        self.final_artifact.is_some()
    }
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
            file_expected_chunks: HashMap::new(),
            file_pk_beta: HashMap::new(),
            file_cycles: HashMap::new(),
            file_owner_contacts: HashMap::new(),
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

    pub fn receive_chunk(&self, chunk: &FileChunk, total_chunks: Option<usize>) -> bool {
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
        if let Some(expected) = total_chunks {
            let entry = inner
                .file_expected_chunks
                .entry(chunk.file_id.clone())
                .or_insert(expected);
            if *entry != expected {
                crate::utils::log_msg(
                    "WARN",
                    "STORE",
                    Some(self.node_id.clone()),
                    &format!(
                        "文件 {} 的期望块数从 {} 调整为 {}。",
                        chunk.file_id, *entry, expected
                    ),
                );
                *entry = expected;
            }
        }
        let file_entry = inner.files.entry(chunk.file_id.clone()).or_default();
        let is_new_chunk = !file_entry.contains_key(&chunk.index);
        file_entry.insert(chunk.index, (chunk.data.clone(), chunk.tag.clone()));
        let commitment = h_join(["commit", &hex::encode(&chunk.tag), &sha256_hex(&chunk.data)]);
        inner
            .storage
            .add_chunk_commitment(&chunk.file_id, chunk.index, commitment);
        if is_new_chunk {
            inner.used_space += inner.chunk_size;
        }
        true
    }

    pub fn set_file_owner_contact(&self, file_id: &str, addr: SocketAddr) {
        let mut inner = self.inner.lock();
        inner
            .file_owner_contacts
            .entry(file_id.to_string())
            .or_insert(addr);
    }

    pub fn get_file_owner_contact(&self, file_id: &str) -> Option<SocketAddr> {
        let inner = self.inner.lock();
        inner.file_owner_contacts.get(file_id).copied()
    }

    pub fn ensure_cycle_metadata(
        &self,
        file_id: &str,
        storage_period: usize,
        challenge_size: usize,
    ) {
        let mut inner = self.inner.lock();
        inner
            .file_cycles
            .entry(file_id.to_string())
            .and_modify(|cycle| {
                if cycle.released {
                    *cycle = FileCycleState::new(storage_period, challenge_size);
                }
            })
            .or_insert_with(|| FileCycleState::new(storage_period, challenge_size));
    }

    pub fn finalize_commitments(&self) {
        let mut inner = self.inner.lock();
        inner.storage.build_state();
        // crate::utils::log_msg(
        //     "INFO",
        //     "COMMIT",
        //     Some(self.node_id.clone()),
        //     "已为接收的文件块构建状态树",
        // );
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
        inner
            .files
            .iter()
            .filter_map(|(fid, _)| {
                if inner
                    .file_cycles
                    .get(fid)
                    .map(|cycle| cycle.is_expired())
                    .unwrap_or(false)
                {
                    None
                } else {
                    Some(fid.clone())
                }
            })
            .collect()
    }

    pub fn get_file_data_for_proof(
        &self,
        file_id: &str,
    ) -> Result<(HashMap<usize, Vec<u8>>, DPDPTags), FileDataError> {
        let inner = self.inner.lock();
        if inner
            .file_cycles
            .get(file_id)
            .map(|cycle| cycle.is_expired())
            .unwrap_or(false)
        {
            return Err(FileDataError::Expired);
        }
        let file_data = inner
            .files
            .get(file_id)
            .cloned()
            .ok_or(FileDataError::NotFound)?;
        let expected = inner
            .file_expected_chunks
            .get(file_id)
            .copied()
            .ok_or_else(|| FileDataError::Incomplete {
                missing_indices: Vec::new(),
            })?;
        let mut missing = Vec::new();
        for idx in 0..expected {
            if !file_data.contains_key(&idx) {
                missing.push(idx);
            }
        }
        if !missing.is_empty() {
            return Err(FileDataError::Incomplete {
                missing_indices: missing,
            });
        }
        let mut chunks = HashMap::new();
        let mut tags = Vec::new();
        let mut sorted: Vec<(usize, (Vec<u8>, Vec<u8>))> = file_data.into_iter().collect();
        sorted.sort_by_key(|(idx, _)| *idx);
        for (idx, (data, tag)) in sorted {
            chunks.insert(idx, data);
            tags.push(tag);
        }
        Ok((chunks, DPDPTags { tags }))
    }

    pub fn set_file_pk_beta(&self, file_id: &str, pk_beta: Vec<u8>) {
        let mut inner = self.inner.lock();
        inner.file_pk_beta.insert(file_id.to_string(), pk_beta);
    }

    pub fn get_file_pk_beta(&self, file_id: &str) -> Option<Vec<u8>> {
        let inner = self.inner.lock();
        inner.file_pk_beta.get(file_id).cloned()
    }

    pub fn has_file(&self, file_id: &str) -> bool {
        let inner = self.inner.lock();
        inner.files.contains_key(file_id)
    }

    pub fn is_file_expired(&self, file_id: &str) -> bool {
        let inner = self.inner.lock();
        inner
            .file_cycles
            .get(file_id)
            .map(|cycle| cycle.is_expired())
            .unwrap_or(false)
    }

    pub fn cleanup_completed_files(&self) -> Vec<(String, usize)> {
        let mut inner = self.inner.lock();
        let mut released = Vec::new();
        let chunk_size = inner.chunk_size;

        let completed: Vec<String> = inner
            .file_cycles
            .iter()
            .filter_map(|(fid, cycle)| {
                if cycle.final_artifact.is_some() && !cycle.released {
                    Some(fid.clone())
                } else {
                    None
                }
            })
            .collect();

        if completed.is_empty() {
            return released;
        }

        for fid in completed {
            let mut freed_bytes = 0usize;
            if let Some(chunks) = inner.files.remove(&fid) {
                let chunk_count = chunks.len();
                freed_bytes = chunk_count.saturating_mul(chunk_size);
                inner.used_space = inner.used_space.saturating_sub(freed_bytes);
            }
            inner.file_pk_beta.remove(&fid);
            inner.file_expected_chunks.remove(&fid);
            inner.file_owner_contacts.remove(&fid);
            inner.storage.time_trees.remove(&fid);
            if let Some(tree) = inner.storage.storage_tree.as_mut() {
                tree.file_roots.remove(&fid);
            }
            if let Some(cycle) = inner.file_cycles.get_mut(&fid) {
                cycle.released = true;
            }
            released.push((fid, freed_bytes));
        }

        if !released.is_empty() {
            inner.storage.build_state();
        }

        released
    }
    pub fn challenge_size_for(&self, file_id: &str) -> Option<usize> {
        let inner = self.inner.lock();
        inner
            .file_cycles
            .get(file_id)
            .map(|cycle| cycle.challenge_size)
    }

    pub fn process_round(
        &self,
        file_id: &str,
        block: &Block,
        proof: &DPDPProof,
        challenge: &[(usize, BigUint)],
        contributions: &[(usize, BigUint, Vec<u8>)],
        round_salt: &str,
    ) -> Option<NovaRoundResult> {
        let mut inner = self.inner.lock();
        if inner
            .file_cycles
            .get(file_id)
            .map(|cycle| cycle.is_expired())
            .unwrap_or(false)
        {
            crate::utils::log_msg(
                "DEBUG",
                "Nova",
                Some(self.node_id.clone()),
                &format!("文件 {} 的存储周期已完成，跳过新的折叠轮次。", file_id),
            );
            return None;
        }
        let pk_bytes = inner.file_pk_beta.get(file_id)?.clone();
        let expected_challenge = match inner.file_cycles.get(file_id) {
            Some(cycle) => cycle.challenge_size,
            None => return None,
        };
        if challenge.len() != expected_challenge {
            crate::utils::log_msg(
                "WARN",
                "Nova",
                Some(self.node_id.clone()),
                &format!(
                    "文件 {} 的挑战大小 {} 与预期 {} 不符，忽略本轮。",
                    file_id,
                    challenge.len(),
                    expected_challenge
                ),
            );
            return None;
        }

        let mut before_state = inner.storage.storage_tree.clone().unwrap_or_default();
        before_state.build();

        let mut pending_leaf_updates = Vec::new();
        if let Some(tst) = inner.storage.time_trees.get(file_id) {
            for (idx, mu_i, sigma_bytes) in contributions {
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
                pending_leaf_updates.push((*idx, new_leaf));
            }
        }
        for (idx, new_leaf) in pending_leaf_updates {
            inner.storage.add_chunk_commitment(file_id, idx, new_leaf);
        }
        inner.storage.build_state();

        let after_state = inner.storage.storage_tree.clone().unwrap_or_default();
        let claimed_root = after_state
            .file_roots
            .get(file_id)
            .cloned()
            .unwrap_or_else(|| h_join(["missing_file", file_id]));

        let params = DPDPParams {
            g: G2Projective::generator(),
            u: G1Projective::generator(),
            pk_beta: deserialize_g2(&pk_bytes),
            sk_alpha: BigUint::from(0u32),
        };

        let (dpdp_circuit, valid) = dpdp_verification_relaxed_r1cs(&params, proof, challenge);
        if !valid {
            crate::utils::log_msg(
                "ERROR",
                "Nova",
                Some(self.node_id.clone()),
                &format!("dPDP 证明对文件 {} 验证失败，跳过折叠。", file_id),
            );
            return None;
        }

        let block_circuit = block_validation_relaxed_r1cs(block, &block.prev_hash, block.height);
        let state_circuit =
            state_update_relaxed_r1cs(&before_state, &[(file_id.to_string(), claimed_root)]);

        let result = {
            let cycle = inner.file_cycles.get_mut(file_id)?;
            let next_step = cycle.nova.steps_completed() + 1;
            crate::utils::log_msg(
                "DEBUG",
                "Nova",
                Some(self.node_id.clone()),
                &format!("准备吸收文件 {} 的第 {} 个折叠轮次。", file_id, next_step),
            );
            let result =
                match cycle
                    .nova
                    .absorb_round(vec![dpdp_circuit, block_circuit, state_circuit])
                {
                    Ok(res) => res,
                    Err(NovaFoldingError::CycleComplete) => return None,
                    Err(err) => {
                        crate::utils::log_msg(
                            "ERROR",
                            "Nova",
                            Some(self.node_id.clone()),
                            &format!("文件 {} 的 Nova 折叠失败: {}", file_id, err),
                        );
                        return None;
                    }
                };
            crate::utils::log_msg(
                "INFO",
                "Nova",
                Some(self.node_id.clone()),
                &format!(
                    "文件 {} 完成折叠轮次 {}，累加器 {}。",
                    file_id,
                    result.step_index,
                    fr_to_padded_hex(&result.accumulator)
                ),
            );

            cycle.record_round(result.clone(), challenge.to_vec(), proof.clone());

            if result.step_index >= cycle.storage_period && cycle.final_artifact.is_none() {
                crate::utils::log_msg(
                    "DEBUG",
                    "Nova",
                    Some(self.node_id.clone()),
                    &format!("文件 {} 达到存储周期阈值，尝试生成最终折叠证明。", file_id),
                );
                match cycle.nova.finalize() {
                    Ok(Some(final_proof)) => cycle.set_final_artifact(final_proof),
                    Ok(None) | Err(NovaFoldingError::CycleComplete) => {}
                    Err(err) => {
                        crate::utils::log_msg(
                            "ERROR",
                            "Nova",
                            Some(self.node_id.clone()),
                            &format!("生成文件 {} 的最终折叠失败: {}", file_id, err),
                        );
                    }
                }
                if let Some(artifact) = &cycle.final_artifact {
                    crate::utils::log_msg(
                        "INFO",
                        "Nova",
                        Some(self.node_id.clone()),
                        &format!(
                            "文件 {} 的最终折叠产物已就绪：步数 {}，累加器 {}。",
                            file_id, artifact.steps, artifact.accumulator
                        ),
                    );
                }
            }

            result
        };

        Some(result)
    }

    pub fn drain_pending_rounds(&self) -> HashMap<String, Vec<JsonValue>> {
        let mut inner = self.inner.lock();
        let mut out = HashMap::new();
        for (file_id, cycle) in inner.file_cycles.iter_mut() {
            if cycle.pending_rounds.is_empty() {
                continue;
            }
            let mut rounds = Vec::new();
            while let Some(record) = cycle.pending_rounds.pop_front() {
                let challenge_json: Vec<JsonValue> = record
                    .challenge
                    .iter()
                    .map(|(idx, val)| serde_json::json!([*idx as u64, val.to_string()]))
                    .collect();
                rounds.push(serde_json::json!({
                    "round": record.round,
                    "challenge": challenge_json,
                    "proof": record.proof,
                    "accumulator": record.accumulator,
                }));
            }
            out.insert(file_id.clone(), rounds);
        }
        out
    }

    pub fn take_final_folds(&self) -> HashMap<String, JsonValue> {
        let mut inner = self.inner.lock();
        let mut out = HashMap::new();
        for (file_id, cycle) in inner.file_cycles.iter_mut() {
            if cycle.final_sent {
                continue;
            }
            if let Some(artifact) = cycle.final_artifact.clone() {
                out.insert(
                    file_id.clone(),
                    serde_json::json!({
                        "accumulator": artifact.accumulator,
                        "steps": artifact.steps,
                        "compressed_snark": artifact.compressed_snark,
                        "verifier_key": artifact.verifier_key,
                    }),
                );
                cycle.final_sent = true;
            }
        }
        out
    }
}
