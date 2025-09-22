use std::collections::HashMap;

use indexmap::IndexMap;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::utils::h_join;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSummary {
    pub node_id: String,
    pub proof_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeEntry(pub usize, pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBody {
    #[serde(default)]
    pub selected_k_proofs: Vec<ProofSummary>,
    #[serde(default)]
    pub coinbase_splits: HashMap<String, String>,
    #[serde(default)]
    pub proofs_merkle_tree: IndexMap<String, Vec<String>>,
    #[serde(default)]
    pub dpdp_challenges: HashMap<String, HashMap<String, Vec<ChallengeEntry>>>,
    #[serde(default)]
    pub dpdp_proofs: HashMap<String, HashMap<String, Value>>,
}

impl Default for BlockBody {
    fn default() -> Self {
        Self {
            selected_k_proofs: Vec::new(),
            coinbase_splits: HashMap::new(),
            proofs_merkle_tree: IndexMap::new(),
            dpdp_challenges: HashMap::new(),
            dpdp_proofs: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub height: u64,
    pub prev_hash: String,
    pub seed: String,
    pub leader_id: String,
    pub accum_proof_hash: String,
    pub merkle_roots: HashMap<String, String>,
    pub round_proof_stmt_hash: String,
    pub body: BlockBody,
    #[serde(default)]
    pub time_tree_roots: HashMap<String, HashMap<String, String>>,
    pub bobtail_k: u64,
    pub bobtail_target: String,
    pub timestamp: u128,
}

impl Block {
    pub fn header_hash(&self) -> String {
        let mut merkle_parts: Vec<String> = self
            .merkle_roots
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect();
        merkle_parts.sort();
        h_join(
            [
                "block",
                &self.height.to_string(),
                &self.prev_hash,
                &self.seed,
                &self.leader_id,
                &self.bobtail_k.to_string(),
                &self.bobtail_target,
                &self.timestamp.to_string(),
            ]
            .into_iter()
            .chain(merkle_parts.iter().map(|s| s.as_str())),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub index: usize,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub tag: Vec<u8>,
    pub file_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BobtailProof {
    pub node_id: String,
    pub address: String,
    pub root: String,
    pub nonce: String,
    pub proof_hash: String,
    pub lots: String,
    #[serde(default)]
    pub file_roots: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct DPDPParams {
    pub g: ark_bn254::G2Projective,
    pub u: ark_bn254::G1Projective,
    pub pk_beta: ark_bn254::G2Projective,
    pub sk_alpha: BigUint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPDPTags {
    pub tags: Vec<Vec<u8>>,
}

impl DPDPTags {
    pub fn len(&self) -> usize {
        self.tags.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPDPProof {
    pub mu: String,
    #[serde(with = "serde_bytes")]
    pub sigma: Vec<u8>,
}
