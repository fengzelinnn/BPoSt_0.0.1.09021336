use std::collections::HashMap;

use num_bigint::BigUint;

use crate::common::datastructures::{DPDPProof, DPDPTags};
use crate::crypto::dpdp::DPDP;
use crate::utils::log_msg;

pub struct Prover {
    pub node_id: String,
}

impl Prover {
    pub fn new(node_id: String) -> Self {
        Self { node_id }
    }

    pub fn prove(
        &self,
        file_id: &str,
        _indices: &[usize],
        file_chunks: &HashMap<usize, Vec<u8>>,
        file_tags: &DPDPTags,
        prev_hash: &str,
        timestamp: u64,
    ) -> (
        DPDPProof,
        Vec<(usize, BigUint)>,
        Vec<(usize, BigUint, Vec<u8>)>,
    ) {
        let challenge = DPDP::gen_chal(prev_hash, timestamp, file_tags, None);
        let proof = DPDP::gen_proof(file_tags, file_chunks, &challenge);
        let contributions = DPDP::gen_contributions(file_tags, file_chunks, &challenge);
        log_msg(
            "DEBUG",
            "dPDP",
            Some(self.node_id.clone()),
            &format!("为文件 {} 生成了dPDP证明与未聚合贡献", file_id),
        );
        (proof, challenge, contributions)
    }
}
