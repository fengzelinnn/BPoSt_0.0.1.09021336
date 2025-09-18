use ark_bn254::{Bn254, Fq, Fq12, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use num_bigint::BigUint;

use crate::common::datastructures::{Block, DPDPParams, DPDPProof};
use crate::crypto::deserialize_g1;
use crate::crypto::dpdp::hash_to_g1;
use crate::storage::state::StorageStateTree;
use crate::utils::h_join;

/// A single constraint inside a relaxed R1CS relation.
#[derive(Debug, Clone)]
pub struct RelaxedR1CSConstraint<F: PrimeField> {
    pub a: Vec<(usize, F)>,
    pub b: Vec<(usize, F)>,
    pub c: Vec<(usize, F)>,
    pub slack: F,
}

impl<F: PrimeField> RelaxedR1CSConstraint<F> {
    pub fn new(a: Vec<(usize, F)>, b: Vec<(usize, F)>, c: Vec<(usize, F)>, slack: F) -> Self {
        Self { a, b, c, slack }
    }
}

/// A lightweight container describing a relaxed R1CS instance.
#[derive(Debug, Clone)]
pub struct RelaxedR1CS<F: PrimeField> {
    pub num_variables: usize,
    pub num_constraints: usize,
    pub inputs: Vec<F>,
    pub witness: Vec<F>,
    pub constraints: Vec<RelaxedR1CSConstraint<F>>,
    assignments: Vec<F>,
}

impl<F: PrimeField> RelaxedR1CS<F> {
    /// Checks whether the stored assignments satisfy all constraints.
    pub fn is_satisfied(&self) -> bool {
        let eval = |lc: &[(usize, F)], assignments: &[F]| -> F {
            lc.iter().fold(F::zero(), |acc, (idx, coeff)| {
                let val = assignments.get(*idx).copied().unwrap_or_else(F::zero);
                acc + val * coeff
            })
        };

        self.constraints.iter().all(|constraint| {
            let a = eval(&constraint.a, &self.assignments);
            let b = eval(&constraint.b, &self.assignments);
            let c = eval(&constraint.c, &self.assignments);
            a * b == c + constraint.slack
        })
    }

    /// Returns the serialized witness for downstream folding operations.
    pub fn witness_serialized(&self) -> Vec<Vec<u8>> {
        self.witness
            .iter()
            .map(|value| {
                let bigint = (*value).into_bigint();
                let bytes = bigint.to_bytes_be();
                let mut out = vec![0u8; 32];
                let start = out.len().saturating_sub(bytes.len());
                out[start..start + bytes.len()].copy_from_slice(&bytes);
                out
            })
            .collect()
    }
}

/// Builder used to construct relaxed R1CS instances.
#[derive(Debug, Clone)]
pub struct RelaxedR1CSBuilder<F: PrimeField> {
    assignments: Vec<F>,
    is_input: Vec<bool>,
    input_indexes: Vec<usize>,
    constraints: Vec<RelaxedR1CSConstraint<F>>,
}

impl<F: PrimeField> RelaxedR1CSBuilder<F> {
    pub fn new() -> Self {
        Self {
            assignments: vec![F::one()],
            is_input: vec![false],
            input_indexes: Vec::new(),
            constraints: Vec::new(),
        }
    }

    fn alloc_variable(&mut self, value: F) -> usize {
        let idx = self.assignments.len();
        self.assignments.push(value);
        self.is_input.push(false);
        idx
    }

    pub fn alloc_input(&mut self, value: F) -> usize {
        let idx = self.alloc_variable(value);
        self.is_input[idx] = true;
        self.input_indexes.push(idx);
        idx
    }

    pub fn alloc_witness(&mut self, value: F) -> usize {
        self.alloc_variable(value)
    }

    pub fn alloc_constant(&mut self, value: F) -> usize {
        let idx = self.alloc_witness(value);
        let mut a = vec![(idx, F::one())];
        if !value.is_zero() {
            a.push((0, -value));
        }
        self.constraints.push(RelaxedR1CSConstraint::new(
            a,
            vec![(0, F::one())],
            Vec::new(),
            F::zero(),
        ));
        idx
    }

    pub fn enforce_equal(&mut self, left: usize, right: usize) {
        self.constraints.push(RelaxedR1CSConstraint::new(
            vec![(left, F::one()), (right, -F::one())],
            vec![(0, F::one())],
            Vec::new(),
            F::zero(),
        ));
    }

    pub fn enforce_boolean(&mut self, var: usize) {
        let minus_one = self.assignments[var] - F::one();
        let minus_one_idx = self.alloc_witness(minus_one);
        // var * (var - 1) = 0
        self.constraints.push(RelaxedR1CSConstraint::new(
            vec![(var, F::one())],
            vec![(minus_one_idx, F::one())],
            Vec::new(),
            F::zero(),
        ));
        // Ensure minus_one_idx stores var - 1
        let mut a = vec![(minus_one_idx, F::one()), (var, -F::one())];
        a.push((0, F::one()));
        self.constraints.push(RelaxedR1CSConstraint::new(
            a,
            vec![(0, F::one())],
            Vec::new(),
            F::zero(),
        ));
    }

    pub fn mul(&mut self, left: usize, right: usize) -> usize {
        let value = self.assignments[left] * self.assignments[right];
        let out = self.alloc_witness(value);
        self.constraints.push(RelaxedR1CSConstraint::new(
            vec![(left, F::one())],
            vec![(right, F::one())],
            vec![(out, F::one())],
            F::zero(),
        ));
        out
    }

    pub fn linear_combination(&mut self, terms: &[(usize, F)], constant: F) -> usize {
        let mut value = constant;
        for (idx, coeff) in terms {
            value += self.assignments[*idx] * coeff;
        }
        let out = self.alloc_witness(value);
        let mut a = vec![(out, F::one())];
        for (idx, coeff) in terms {
            a.push((*idx, -(*coeff)));
        }
        if !constant.is_zero() {
            a.push((0, -constant));
        }
        self.constraints.push(RelaxedR1CSConstraint::new(
            a,
            vec![(0, F::one())],
            Vec::new(),
            F::zero(),
        ));
        out
    }

    pub fn finish(self) -> RelaxedR1CS<F> {
        let Self {
            assignments,
            is_input,
            input_indexes,
            constraints,
        } = self;

        let inputs = input_indexes
            .iter()
            .map(|&idx| assignments[idx])
            .collect::<Vec<_>>();
        let witness = assignments
            .iter()
            .enumerate()
            .skip(1)
            .filter_map(|(idx, value)| if is_input[idx] { None } else { Some(*value) })
            .collect::<Vec<_>>();

        RelaxedR1CS {
            num_variables: assignments.len() - 1,
            num_constraints: constraints.len(),
            inputs,
            witness,
            constraints,
            assignments,
        }
    }
}

fn fq_to_fr(value: &Fq) -> Fr {
    let mut bytes = value.into_bigint().to_bytes_be();
    if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    Fr::from_be_bytes_mod_order(&bytes)
}

fn fq12_to_fr_vec(value: Fq12) -> Vec<Fr> {
    let mut coeffs = Vec::with_capacity(12);
    let c0 = value.c0;
    let c1 = value.c1;
    for fq6 in [c0, c1] {
        for fq2 in [fq6.c0, fq6.c1, fq6.c2] {
            coeffs.push(fq_to_fr(&fq2.c0));
            coeffs.push(fq_to_fr(&fq2.c1));
        }
    }
    coeffs
}

fn biguint_to_fr(value: &BigUint) -> Fr {
    let mut bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    Fr::from_be_bytes_mod_order(&bytes)
}

fn fr_from_hex(hex_str: &str) -> Fr {
    let decoded = hex::decode(hex_str).unwrap_or_default();
    let mut bytes = [0u8; 32];
    if decoded.len() >= 32 {
        bytes.copy_from_slice(&decoded[decoded.len() - 32..]);
    } else {
        bytes[32 - decoded.len()..].copy_from_slice(&decoded);
    }
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Builds the relaxed R1CS circuit for dPDP verification.
pub fn dpdp_verification_relaxed_r1cs(
    params: &DPDPParams,
    proof: &DPDPProof,
    challenge: &[(usize, BigUint)],
) -> (RelaxedR1CS<Fr>, bool) {
    let sigma = deserialize_g1(&proof.sigma);
    let sigma_affine = G1Affine::from(sigma);
    let g_affine = G2Affine::from(params.g);
    let lhs = Bn254::pairing(sigma_affine, g_affine);

    let mut agg_h = G1Projective::zero();
    for (index, value) in challenge {
        let h_i = hash_to_g1(index.to_string().as_bytes());
        let scalar = biguint_to_fr(value);
        agg_h += h_i.mul_bigint(scalar.into_bigint());
    }

    let mu_big = BigUint::parse_bytes(proof.mu.as_bytes(), 10).unwrap_or_default();
    let mu_fr = biguint_to_fr(&mu_big);
    let mu_u = params.u.mul_bigint(mu_fr.into_bigint());
    let rhs_point = agg_h + mu_u;
    let rhs = Bn254::pairing(G1Affine::from(rhs_point), G2Affine::from(params.pk_beta));
    let valid = lhs == rhs;

    let mut builder = RelaxedR1CSBuilder::<Fr>::new();
    let mu_input = builder.alloc_input(mu_fr);
    let mu_witness = builder.alloc_witness(mu_fr);
    builder.enforce_equal(mu_input, mu_witness);

    let validity_var = builder.alloc_input(if valid { Fr::one() } else { Fr::zero() });
    builder.enforce_boolean(validity_var);

    let lhs_coeffs = fq12_to_fr_vec(lhs.0);
    let rhs_coeffs = fq12_to_fr_vec(rhs.0);
    let mut diff_squares = Vec::new();

    for (lhs_coeff, rhs_coeff) in lhs_coeffs.iter().zip(rhs_coeffs.iter()) {
        let lhs_var = builder.alloc_witness(*lhs_coeff);
        let rhs_var = builder.alloc_witness(*rhs_coeff);
        let diff =
            builder.linear_combination(&[(lhs_var, Fr::one()), (rhs_var, -Fr::one())], Fr::zero());
        let diff_sq = builder.mul(diff, diff);
        diff_squares.push(diff_sq);
    }

    let sum_var = if diff_squares.is_empty() {
        builder.alloc_constant(Fr::zero())
    } else {
        let mut acc = diff_squares[0];
        for diff_sq in diff_squares.iter().copied().skip(1) {
            acc = builder.linear_combination(&[(acc, Fr::one()), (diff_sq, Fr::one())], Fr::zero());
        }
        acc
    };

    let product = builder.mul(sum_var, validity_var);
    let zero = builder.alloc_constant(Fr::zero());
    builder.enforce_equal(product, zero);

    let circuit = builder.finish();
    (circuit, valid)
}

/// Builds the relaxed R1CS circuit for validating a block header.
pub fn block_validation_relaxed_r1cs(
    block: &Block,
    expected_prev_hash: &str,
    expected_height: u64,
) -> RelaxedR1CS<Fr> {
    let mut builder = RelaxedR1CSBuilder::<Fr>::new();

    let prev_hash_var = builder.alloc_input(fr_from_hex(&block.prev_hash));
    let expected_prev_hash_var = builder.alloc_input(fr_from_hex(expected_prev_hash));
    builder.enforce_equal(prev_hash_var, expected_prev_hash_var);

    let height_var = builder.alloc_input(Fr::from(block.height));
    let expected_height_var = builder.alloc_input(Fr::from(expected_height));
    builder.enforce_equal(height_var, expected_height_var);

    let proofs_count = Fr::from(block.body.selected_k_proofs.len() as u64);
    let proofs_var = builder.alloc_input(proofs_count);
    let bobtail_k_var = builder.alloc_input(Fr::from(block.bobtail_k));
    builder.enforce_equal(proofs_var, bobtail_k_var);

    let header_hash = block.header_hash();
    let header_var = builder.alloc_input(fr_from_hex(&header_hash));
    let recomputed_header = builder.alloc_witness(fr_from_hex(&header_hash));
    builder.enforce_equal(header_var, recomputed_header);

    builder.finish()
}

/// Builds the relaxed R1CS circuit for validating storage state updates.
pub fn state_update_relaxed_r1cs(
    state: &StorageStateTree,
    updates: &[(String, String)],
) -> RelaxedR1CS<Fr> {
    let mut builder = RelaxedR1CSBuilder::<Fr>::new();

    let mut before = state.clone();
    before.build();
    let before_root = before.root();
    let before_var = builder.alloc_input(fr_from_hex(&before_root));
    let before_copy = builder.alloc_witness(fr_from_hex(&before_root));
    builder.enforce_equal(before_var, before_copy);

    let mut after = before.clone();
    for (file_id, new_root) in updates {
        after.file_roots.insert(file_id.clone(), new_root.clone());
    }
    after.build();
    let after_root = after.root();
    let after_var = builder.alloc_input(fr_from_hex(&after_root));
    let after_copy = builder.alloc_witness(fr_from_hex(&after_root));
    builder.enforce_equal(after_var, after_copy);

    let diff = builder.linear_combination(
        &[(after_var, Fr::one()), (before_var, -Fr::one())],
        Fr::zero(),
    );
    let diff_sq = builder.mul(diff, diff);
    let same_flag = if before_root == after_root {
        Fr::one()
    } else {
        Fr::zero()
    };
    let same_var = builder.alloc_input(same_flag);
    builder.enforce_boolean(same_var);
    let product = builder.mul(diff_sq, same_var);
    let zero = builder.alloc_constant(Fr::zero());
    builder.enforce_equal(product, zero);

    for (file_id, new_root) in updates {
        let final_value = after
            .file_roots
            .get(file_id)
            .cloned()
            .unwrap_or_else(|| h_join(["missing_final", file_id]));
        let final_var = builder.alloc_witness(fr_from_hex(&final_value));
        let claimed_var = builder.alloc_input(fr_from_hex(new_root));
        builder.enforce_equal(final_var, claimed_var);
    }

    builder.finish()
}

/// Accumulates relaxed R1CS instances that will later be folded by Nova.
#[derive(Debug, Clone)]
pub struct IncrementalRelaxedCircuit<F: PrimeField> {
    pub steps: Vec<RelaxedR1CS<F>>,
    pub accumulator: F,
}

impl<F: PrimeField> IncrementalRelaxedCircuit<F> {
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            accumulator: F::zero(),
        }
    }

    pub fn absorb(&mut self, circuit: RelaxedR1CS<F>) {
        let delta = F::from((self.steps.len() + 1) as u64);
        self.accumulator += delta;
        self.steps.push(circuit);
    }

    pub fn merge(&mut self, other: &Self) {
        self.accumulator += other.accumulator;
        self.steps.extend(other.steps.clone());
    }

    pub fn total_constraints(&self) -> usize {
        self.steps
            .iter()
            .map(|circuit| circuit.num_constraints)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{G1Projective, G2Projective};
    use ark_ec::PrimeGroup;
    use indexmap::IndexMap;
    use std::collections::HashMap;

    use crate::common::datastructures::{BlockBody, DPDPParams};
    use crate::crypto::dpdp::DPDP;
    use crate::crypto::serialize_g1;
    use crate::storage::state::StorageStateTree;

    #[test]
    fn dpdp_relaxed_circuit_matches_verifier() {
        let params = DPDP::key_gen();
        let file_chunks = vec![b"chunk0".to_vec(), b"chunk1".to_vec()];
        let tags = DPDP::tag_file(&params, &file_chunks);
        let mut chunk_map = HashMap::new();
        for (idx, chunk) in file_chunks.iter().enumerate() {
            chunk_map.insert(idx, chunk.clone());
        }
        let challenge = DPDP::gen_chal("prev", 42, &tags, Some(2));
        let proof = DPDP::gen_proof(&tags, &chunk_map, &challenge);
        let (circuit, valid) = dpdp_verification_relaxed_r1cs(&params, &proof, &challenge);
        assert!(valid);
        assert!(circuit.is_satisfied());
    }

    #[test]
    fn block_relaxed_circuit_checks_height_and_prev_hash() {
        let mut merkle_roots = HashMap::new();
        merkle_roots.insert("storage".to_string(), h_join(["root"]));
        let body = BlockBody {
            selected_k_proofs: vec![],
            coinbase_splits: HashMap::new(),
            proofs_merkle_tree: IndexMap::new(),
            dpdp_challenges: HashMap::new(),
        };
        let block = Block {
            height: 1,
            prev_hash: h_join(["prev"]),
            seed: h_join(["seed"]),
            leader_id: "node1".into(),
            accum_proof_hash: h_join(["acc"]),
            merkle_roots,
            round_proof_stmt_hash: h_join(["stmt"]),
            body,
            time_tree_roots: HashMap::new(),
            bobtail_k: 0,
            bobtail_target: h_join(["target"]),
            timestamp: 0,
        };
        let circuit = block_validation_relaxed_r1cs(&block, &block.prev_hash, block.height);
        assert!(circuit.is_satisfied());
    }

    #[test]
    fn state_update_relaxed_circuit_tracks_merkle_root() {
        let mut tree = StorageStateTree::default();
        tree.file_roots.insert("file1".into(), h_join(["leaf0"]));
        tree.build();
        let updates = vec![("file1".to_string(), h_join(["leaf1"]))];
        let circuit = state_update_relaxed_r1cs(&tree, &updates);
        assert!(circuit.is_satisfied());
    }

    #[test]
    fn incremental_relaxed_circuit_accumulates_steps() {
        let mut accumulator = IncrementalRelaxedCircuit::<Fr>::new();
        let params = DPDPParams {
            g: G2Projective::generator(),
            u: G1Projective::generator(),
            pk_beta: G2Projective::generator(),
            sk_alpha: BigUint::from(1u32),
        };
        let proof = DPDPProof {
            mu: "0".into(),
            sigma: serialize_g1(&G1Projective::zero()),
        };
        let (circuit, _) = dpdp_verification_relaxed_r1cs(&params, &proof, &[]);
        accumulator.absorb(circuit.clone());
        accumulator.absorb(circuit);
        assert_eq!(accumulator.steps.len(), 2);
        assert!(accumulator.accumulator != Fr::zero());
        assert!(accumulator.total_constraints() > 0);
    }
}
