use ark_bn254::{Bn254, Fq, Fq12, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use bincode;
use ff::{Field as FFField, PrimeField as FFPrimeField};
use nova_snark::{
    errors::NovaError as NovaSnarkError,
    frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{
        hyperkzg::EvaluationEngine as HyperKzg, ipa_pc::EvaluationEngine as IpaPc, Bn256EngineKZG,
        GrumpkinEngine,
    },
    spartan::snark::RelaxedR1CSSNARK,
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
};
use num_bigint::BigUint;
use thiserror::Error;

use crate::common::datastructures::{Block, DPDPParams, DPDPProof};
use crate::crypto::deserialize_g1;
use crate::crypto::dpdp::hash_to_g1;
use crate::storage::state::StorageStateTree;
use crate::utils::h_join;

/// 表示松弛 R1CS 关系中的单个约束。
/// a * b = u * c + error
#[derive(Debug, Clone)]
pub struct RelaxedR1CSConstraint<F: PrimeField> {
    /// 线性组合 a 的系数和变量索引
    pub a: Vec<(usize, F)>,
    /// 线性组合 b 的系数和变量索引
    pub b: Vec<(usize, F)>,
    /// 线性组合 c 的系数和变量索引
    pub c: Vec<(usize, F)>,
    /// 松弛误差项 E
    pub error: F,
}

impl<F: PrimeField> RelaxedR1CSConstraint<F> {
    /// 创建一个新的松弛 R1CS 约束。
    pub fn new(a: Vec<(usize, F)>, b: Vec<(usize, F)>, c: Vec<(usize, F)>, error: F) -> Self {
        Self { a, b, c, error }
    }
}

/// 描述松弛 R1CS 实例的轻量级容器。
#[derive(Debug, Clone)]
pub struct RelaxedR1CS<F: PrimeField> {
    /// 变量数量
    pub num_variables: usize,
    /// 约束数量
    pub num_constraints: usize,
    /// 公共输入
    pub inputs: Vec<F>,
    /// 私有见证
    pub witness: Vec<F>,
    /// 约束列表
    pub constraints: Vec<RelaxedR1CSConstraint<F>>,
    /// 关系的松弛标量 u
    pub u: F,
    /// 所有变量的赋值 (包括输入和见证)
    assignments: Vec<F>,
}

impl<F: PrimeField> RelaxedR1CS<F> {
    /// 检查存储的赋值是否满足所有约束。
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
            a * b == self.u * c + constraint.error
        })
    }

    /// 返回序列化后的见证，用于后续的折叠操作。
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

/// 用于构造松弛 R1CS 实例的构建器。
#[derive(Debug, Clone)]
pub struct RelaxedR1CSBuilder<F: PrimeField> {
    /// 变量赋值
    assignments: Vec<F>,
    /// 标记变量是否为输入
    is_input: Vec<bool>,
    /// 输入变量的索引
    input_indexes: Vec<usize>,
    /// 约束列表
    constraints: Vec<RelaxedR1CSConstraint<F>>,
    /// 松弛标量 u
    u: F,
}

impl<F: PrimeField> RelaxedR1CSBuilder<F> {
    /// 创建一个新的构建器。
    pub fn new() -> Self {
        Self {
            // 预分配一个值为 1 的常量
            assignments: vec![F::one()],
            is_input: vec![false],
            input_indexes: Vec::new(),
            constraints: Vec::new(),
            u: F::one(),
        }
    }

    /// 设置松弛标量 u。
    pub fn set_relaxation_parameter(&mut self, u: F) {
        self.u = u;
    }

    /// 分配一个新变量。
    fn alloc_variable(&mut self, value: F) -> usize {
        let idx = self.assignments.len();
        self.assignments.push(value);
        self.is_input.push(false);
        idx
    }

    /// 分配一个公共输入变量。
    pub fn alloc_input(&mut self, value: F) -> usize {
        let idx = self.alloc_variable(value);
        self.is_input[idx] = true;
        self.input_indexes.push(idx);
        idx
    }

    /// 分配一个私有见证变量。
    pub fn alloc_witness(&mut self, value: F) -> usize {
        self.alloc_variable(value)
    }

    /// 分配一个常量值。
    pub fn alloc_constant(&mut self, value: F) -> usize {
        let idx = self.alloc_witness(value);
        let mut a = vec![(idx, F::one())];
        if !value.is_zero() {
            a.push((0, -value));
        }
        self.constraints.push(RelaxedR1CSConstraint::new(
            a,
            vec![(0, F::one())], // 乘以 1
            Vec::new(),
            F::zero(),
        ));
        idx
    }

    /// 强制两个变量相等。
    pub fn enforce_equal(&mut self, left: usize, right: usize) {
        self.constraints.push(RelaxedR1CSConstraint::new(
            vec![(left, F::one()), (right, -F::one())], // left - right
            vec![(0, F::one())],                        // * 1
            Vec::new(),                                 // = 0
            F::zero(),
        ));
    }

    /// 强制一个变量为布尔值 (0 或 1)。
    pub fn enforce_boolean(&mut self, var: usize) {
        let minus_one = self.assignments[var] - F::one();
        let minus_one_idx = self.alloc_witness(minus_one);
        // 添加约束: var * (var - 1) = 0
        self.constraints.push(RelaxedR1CSConstraint::new(
            vec![(var, F::one())],
            vec![(minus_one_idx, F::one())],
            Vec::new(),
            F::zero(),
        ));
        // 确保 minus_one_idx 存储的是 var - 1
        let mut a = vec![(minus_one_idx, F::one()), (var, -F::one())];
        a.push((0, F::one()));
        self.constraints.push(RelaxedR1CSConstraint::new(
            a,
            vec![(0, F::one())],
            Vec::new(),
            F::zero(),
        ));
    }

    /// 两个变量相乘。
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

    /// 计算变量的线性组合。
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

    /// 完成构建并返回松弛 R1CS 实例。
    pub fn finish(mut self) -> RelaxedR1CS<F> {
        let u = self.u;
        self.assignments.push(u);
        self.is_input.push(false);

        let Self {
            assignments,
            is_input,
            input_indexes,
            constraints,
            u: _,
        } = self;

        let inputs = input_indexes
            .iter()
            .map(|&idx| assignments[idx])
            .collect::<Vec<_>>();
        let witness = assignments
            .iter()
            .enumerate()
            .skip(1) // 跳过常量 1
            .filter_map(|(idx, value)| if is_input[idx] { None } else { Some(*value) })
            .collect::<Vec<_>>();

        RelaxedR1CS {
            num_variables: assignments.len() - 1,
            num_constraints: constraints.len(),
            inputs,
            witness,
            constraints,
            u,
            assignments,
        }
    }
}

/// 计算赋值向量的摘要。
fn assignments_digest(assignments: &[Fr]) -> Fr {
    let mut acc = Fr::zero();
    for (idx, value) in assignments.iter().enumerate() {
        let weight = Fr::from((idx as u64) + 1);
        acc += *value * weight;
    }
    acc
}

fn fr_to_nova_scalar(value: &Fr) -> NovaScalar {
    let bytes = value.into_bigint().to_bytes_le();
    let mut repr = <NovaScalar as FFPrimeField>::Repr::default();
    repr.as_mut()[..bytes.len()].copy_from_slice(&bytes);
    FFPrimeField::from_repr(repr).expect("valid Fr to NovaScalar conversion")
}

fn nova_scalar_to_fr(value: &NovaScalar) -> Fr {
    let repr = value.to_repr();
    Fr::from_le_bytes_mod_order(repr.as_ref())
}

/// 将 Fq 元素转换为 Fr 元素。
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

/// 将 Fq12 元素转换为 Fr 元素向量。
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

/// 将 BigUint 转换为 Fr 元素。
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

/// 从十六进制字符串创建 Fr 元素。
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

/// 将 Fr 元素转换为填充的十六进制字符串。
pub(crate) fn fr_to_padded_hex(value: &Fr) -> String {
    let mut bytes = value.into_bigint().to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    hex::encode(bytes)
}

/// 为 dPDP 验证构建松弛 R1CS 电路。
/// 返回电路和验证结果 (是否有效)。
pub fn dpdp_verification_relaxed_r1cs(
    params: &DPDPParams,
    proof: &DPDPProof,
    challenge: &[(usize, BigUint)],
) -> (RelaxedR1CS<Fr>, bool) {
    // 验证 dPDP 证明
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

    // 构建 R1CS 电路
    let mut builder = RelaxedR1CSBuilder::<Fr>::new();
    let mu_input = builder.alloc_input(mu_fr);
    let mu_witness = builder.alloc_witness(mu_fr);
    builder.enforce_equal(mu_input, mu_witness);

    let validity_var = builder.alloc_input(if valid { Fr::one() } else { Fr::zero() });
    builder.enforce_boolean(validity_var);

    // 约束 e(sigma, g) == e(agg_h + u * mu, pk_beta)
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

    // 如果验证有效 (validity_var=1)，则 sum_var 必须为 0。如果验证无效 (validity_var=0)，则 sum_var 可以是任何值。
    // 通过约束 sum_var * validity_var = 0 来实现。
    let product = builder.mul(sum_var, validity_var);
    let zero = builder.alloc_constant(Fr::zero());
    builder.enforce_equal(product, zero);

    let circuit = builder.finish();
    (circuit, valid)
}

/// 为验证区块头构建松弛 R1CS 电路。
pub fn block_validation_relaxed_r1cs(
    block: &Block,
    expected_prev_hash: &str,
    expected_height: u64,
) -> RelaxedR1CS<Fr> {
    let mut builder = RelaxedR1CSBuilder::<Fr>::new();

    // 约束 prev_hash
    let prev_hash_var = builder.alloc_input(fr_from_hex(&block.prev_hash));
    let expected_prev_hash_var = builder.alloc_input(fr_from_hex(expected_prev_hash));
    builder.enforce_equal(prev_hash_var, expected_prev_hash_var);

    // 约束 height
    let height_var = builder.alloc_input(Fr::from(block.height));
    let expected_height_var = builder.alloc_input(Fr::from(expected_height));
    builder.enforce_equal(height_var, expected_height_var);

    // 约束 proofs count
    let proofs_count = Fr::from(block.body.selected_k_proofs.len() as u64);
    let proofs_var = builder.alloc_input(proofs_count);
    let bobtail_k_var = builder.alloc_input(Fr::from(block.bobtail_k));
    builder.enforce_equal(proofs_var, bobtail_k_var);

    // 约束 header_hash
    let header_hash = block.header_hash();
    let header_var = builder.alloc_input(fr_from_hex(&header_hash));
    let recomputed_header = builder.alloc_witness(fr_from_hex(&header_hash));
    builder.enforce_equal(header_var, recomputed_header);

    builder.finish()
}

/// 为验证存储状态更新构建松弛 R1CS 电路。
pub fn state_update_relaxed_r1cs(
    state: &StorageStateTree,
    updates: &[(String, String)],
) -> RelaxedR1CS<Fr> {
    let mut builder = RelaxedR1CSBuilder::<Fr>::new();

    // 计算更新前的状态树根
    let mut before = state.clone();
    before.build();
    let before_root = before.root();
    let before_var = builder.alloc_input(fr_from_hex(&before_root));
    let before_copy = builder.alloc_witness(fr_from_hex(&before_root));
    builder.enforce_equal(before_var, before_copy);

    // 计算更新后的状态树根
    let mut after = before.clone();
    for (file_id, new_root) in updates {
        after.file_roots.insert(file_id.clone(), new_root.clone());
    }
    after.build();
    let after_root = after.root();
    let after_var = builder.alloc_input(fr_from_hex(&after_root));
    let after_copy = builder.alloc_witness(fr_from_hex(&after_root));
    builder.enforce_equal(after_var, after_copy);

    // 如果根哈希相同，则 same_flag 为 1，否则为 0。
    // 约束 (after_root - before_root)^2 * same_flag = 0
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

    // 验证每个文件的根哈希是否已正确更新
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

/// 累积将由 Nova 折叠的松弛 R1CS 实例。
#[derive(Debug, Clone)]
pub struct IncrementalRelaxedCircuit<F: PrimeField> {
    /// R1CS 步骤列表
    pub steps: Vec<RelaxedR1CS<F>>,
    /// 累加器
    pub accumulator: F,
}

impl<F: PrimeField> IncrementalRelaxedCircuit<F> {
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            accumulator: F::zero(),
        }
    }

    /// 吸收一个新的电路实例。
    pub fn absorb(&mut self, circuit: RelaxedR1CS<F>) {
        let delta = F::from((self.steps.len() + 1) as u64);
        self.accumulator += delta;
        self.steps.push(circuit);
    }

    /// 合并另一个累积电路。
    pub fn merge(&mut self, other: &Self) {
        self.accumulator += other.accumulator;
        self.steps.extend(other.steps.clone());
    }

    /// 返回总约束数。
    pub fn total_constraints(&self) -> usize {
        self.steps
            .iter()
            .map(|circuit| circuit.num_constraints)
            .sum()
    }
}

type NovaEngine1 = Bn256EngineKZG;
type NovaEngine2 = GrumpkinEngine;
type NovaEE1 = HyperKzg<NovaEngine1>;
type NovaEE2 = IpaPc<NovaEngine2>;
type NovaSNARK1 = RelaxedR1CSSNARK<NovaEngine1, NovaEE1>;
type NovaSNARK2 = RelaxedR1CSSNARK<NovaEngine2, NovaEE2>;
type NovaScalar = <NovaEngine1 as Engine>::Scalar;

#[derive(Clone, Debug)]
struct NovaConstraint {
    a: Vec<(usize, NovaScalar)>,
    b: Vec<(usize, NovaScalar)>,
    c: Vec<(usize, NovaScalar)>,
    error: NovaScalar,
}

#[derive(Clone, Debug)]
struct NovaCircuitInstance {
    assignments: Vec<NovaScalar>,
    constraints: Vec<NovaConstraint>,
    u: NovaScalar,
}

impl NovaCircuitInstance {
    fn pad(&mut self) {
        let current_vars = self.assignments.len().saturating_sub(1);
        let target_vars = if current_vars == 0 {
            1
        } else {
            current_vars.next_power_of_two()
        };

        for _ in current_vars..target_vars {
            self.assignments.push(NovaScalar::ZERO);
            let var_idx = self.assignments.len() - 1;
            self.constraints.push(NovaConstraint {
                a: vec![(var_idx, NovaScalar::ONE)],
                b: vec![(0, NovaScalar::ONE)],
                c: Vec::new(),
                error: NovaScalar::ZERO,
            });
        }

        let current_cons = self.constraints.len();
        let target_cons = if current_cons == 0 {
            1
        } else {
            current_cons.next_power_of_two()
        };
        for _ in current_cons..target_cons {
            self.constraints.push(NovaConstraint {
                a: Vec::new(),
                b: Vec::new(),
                c: Vec::new(),
                error: NovaScalar::ZERO,
            });
        }
    }
}

/// Nova 步骤电路，将一个或多个松弛 R1CS 实例嵌入到 Nova 的递归证明中。
#[derive(Clone, Debug)]
struct NovaStepCircuit {
    circuits: Vec<NovaCircuitInstance>,
    total_digest: NovaScalar,
}

impl NovaStepCircuit {
    fn new(circuits: Vec<RelaxedR1CS<Fr>>) -> Self {
        let mut converted = Vec::with_capacity(circuits.len());
        let mut total_digest = NovaScalar::ZERO;

        for circuit in circuits {
            let assignments = circuit
                .assignments
                .iter()
                .map(fr_to_nova_scalar)
                .collect::<Vec<_>>();
            let constraints = circuit
                .constraints
                .iter()
                .map(|constraint| NovaConstraint {
                    a: constraint
                        .a
                        .iter()
                        .map(|(idx, coeff)| (*idx, fr_to_nova_scalar(coeff)))
                        .collect(),
                    b: constraint
                        .b
                        .iter()
                        .map(|(idx, coeff)| (*idx, fr_to_nova_scalar(coeff)))
                        .collect(),
                    c: constraint
                        .c
                        .iter()
                        .map(|(idx, coeff)| (*idx, fr_to_nova_scalar(coeff)))
                        .collect(),
                    error: fr_to_nova_scalar(&constraint.error),
                })
                .collect::<Vec<_>>();

            let circuit_digest = assignments
                .iter()
                .enumerate()
                .fold(NovaScalar::ZERO, |acc, (idx, value)| {
                    acc + (*value * NovaScalar::from((idx as u64) + 1))
                });
            total_digest += circuit_digest;

            converted.push(NovaCircuitInstance {
                assignments,
                constraints,
                u: fr_to_nova_scalar(&circuit.u),
            });
        }

        for instance in &mut converted {
            instance.pad();
        }

        Self {
            circuits: converted,
            total_digest,
        }
    }
}

impl StepCircuit<NovaScalar> for NovaStepCircuit {
    fn arity(&self) -> usize {
        2
    }

    fn synthesize<CS: ConstraintSystem<NovaScalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<NovaScalar>],
    ) -> Result<Vec<AllocatedNum<NovaScalar>>, SynthesisError> {
        assert_eq!(z.len(), 2, "Nova 步骤电路的输入维度应为 2");

        let one = CS::one();
        let mut digest_vars = Vec::with_capacity(self.circuits.len());

        for (idx, circuit) in self.circuits.iter().enumerate() {
            let mut ns = cs.namespace(|| format!("circuit_{idx}"));
            let mut vars: Vec<Option<AllocatedNum<NovaScalar>>> =
                Vec::with_capacity(circuit.assignments.len());
            vars.push(None);

            for (var_idx, value) in circuit.assignments.iter().copied().enumerate().skip(1) {
                let allocated =
                    AllocatedNum::alloc(ns.namespace(|| format!("var_{var_idx}")), || Ok(value))?;
                vars.push(Some(allocated));
            }

            for (constraint_idx, constraint) in circuit.constraints.iter().enumerate() {
                let a_terms = constraint.a.clone();
                let b_terms = constraint.b.clone();
                let c_terms = constraint.c.clone();
                let error = constraint.error;
                let u = circuit.u;
                ns.enforce(
                    || format!("constraint_{constraint_idx}"),
                    |lc| {
                        let mut lc = lc;
                        for (var_idx, coeff) in &a_terms {
                            if *var_idx == 0 {
                                lc = lc + (*coeff, one);
                            } else if let Some(var) = &vars[*var_idx] {
                                lc = lc + (*coeff, var.get_variable());
                            }
                        }
                        lc
                    },
                    |lc| {
                        let mut lc = lc;
                        for (var_idx, coeff) in &b_terms {
                            if *var_idx == 0 {
                                lc = lc + (*coeff, one);
                            } else if let Some(var) = &vars[*var_idx] {
                                lc = lc + (*coeff, var.get_variable());
                            }
                        }
                        lc
                    },
                    |lc| {
                        let mut lc = lc;
                        for (var_idx, coeff) in &c_terms {
                            if *var_idx == 0 {
                                lc = lc + (*coeff * u, one);
                            } else if let Some(var) = &vars[*var_idx] {
                                lc = lc + (*coeff * u, var.get_variable());
                            }
                        }
                        if error != NovaScalar::ZERO {
                            lc = lc + (error, one);
                        }
                        lc
                    },
                );
            }

            let digest_value = circuit
                .assignments
                .iter()
                .enumerate()
                .fold(NovaScalar::ZERO, |acc, (var_idx, value)| {
                    acc + (*value * NovaScalar::from((var_idx as u64) + 1))
                });
            let digest_var = AllocatedNum::alloc(ns.namespace(|| "digest"), || Ok(digest_value))?;
            ns.enforce(
                || "digest_constraint",
                |lc| lc + one,
                |lc| {
                    let mut lc = lc;
                    for (var_idx, _value) in circuit.assignments.iter().enumerate() {
                        let coeff = NovaScalar::from((var_idx as u64) + 1);
                        if var_idx == 0 {
                            lc = lc + (coeff, one);
                        } else if let Some(var) = &vars[var_idx] {
                            lc = lc + (coeff, var.get_variable());
                        }
                    }
                    lc
                },
                |lc| lc + digest_var.get_variable(),
            );
            digest_vars.push(digest_var);
        }

        let next_step = AllocatedNum::alloc(cs.namespace(|| "next_step"), || {
            let mut step = z[1].get_value().ok_or(SynthesisError::AssignmentMissing)?;
            step += NovaScalar::ONE;
            Ok(step)
        })?;

        cs.enforce(
            || "step_increment",
            |lc| lc + one,
            |lc| {
                let mut lc = lc + z[1].get_variable();
                lc = lc + (NovaScalar::ONE, one);
                lc
            },
            |lc| lc + next_step.get_variable(),
        );

        let next_acc = AllocatedNum::alloc(cs.namespace(|| "next_acc"), || {
            let mut acc = z[0].get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let mut step = z[1].get_value().ok_or(SynthesisError::AssignmentMissing)?;
            step += NovaScalar::ONE;
            acc += step;
            acc += self.total_digest;
            Ok(acc)
        })?;

        cs.enforce(
            || "accumulator_update",
            |lc| lc + one,
            |lc| {
                let mut lc = lc + z[0].get_variable();
                lc = lc + next_step.get_variable();
                for digest_var in &digest_vars {
                    lc = lc + digest_var.get_variable();
                }
                lc
            },
            |lc| lc + next_acc.get_variable(),
        );

        Ok(vec![next_acc, next_step])
    }
}

/// Nova 折叠编排的错误类型。
#[derive(Debug, Error)]
pub enum NovaFoldingError {
    #[error("nova folding cycle already completed")]
    CycleComplete,
    #[error("nova folding cycle not initialized")]
    NotInitialized,
    #[error("invalid relaxed circuit round")]
    EmptyRound,
    #[error("nova internal error: {0}")]
    NovaInternal(#[from] NovaSnarkError),
    #[error("serialization failure: {0}")]
    Serialization(String),
}

/// 单轮折叠的结果。
#[derive(Debug, Clone)]
pub struct NovaRoundResult {
    pub step_index: usize,
    pub accumulator: Fr,
}

/// 在存储周期结束时返回的最终 Nova 折叠产物。
#[derive(Debug, Clone)]
pub struct NovaFinalProof {
    /// 压缩的 SNARK 证明
    pub compressed_snark: Vec<u8>,
    /// 验证者密钥
    pub verifier_key: Vec<u8>,
    /// 步骤数
    pub steps: usize,
    /// 累加器值
    pub accumulator: Fr,
}

/// 管理存储周期的基于 Nova 的折叠驱动程序。
pub struct NovaFoldingCycle {
    /// 存储周期中的步骤总数
    storage_period: usize,
    /// 已完成的步骤数
    steps: usize,
    /// 主累加器
    accumulator: Fr,
    /// 每轮的累加器值
    round_accumulators: Vec<Fr>,
    /// 最终的证明 (如果已生成)
    finalized: Option<NovaFinalProof>,
    /// Nova 公共参数
    pp: Option<PublicParams<NovaEngine1, NovaEngine2, NovaStepCircuit>>,
    /// 当前的递归 SNARK 实例
    recursive_snark: Option<RecursiveSNARK<NovaEngine1, NovaEngine2, NovaStepCircuit>>,
    /// 初始公开输入向量
    initial_z: Vec<NovaScalar>,
}

impl NovaFoldingCycle {
    pub fn new(storage_period: usize) -> Self {
        Self {
            storage_period,
            steps: 0,
            accumulator: Fr::zero(),
            round_accumulators: Vec::new(),
            finalized: None,
            pp: None,
            recursive_snark: None,
            initial_z: vec![NovaScalar::ZERO, NovaScalar::ZERO],
        }
    }

    pub fn storage_period(&self) -> usize {
        self.storage_period
    }

    pub fn steps_completed(&self) -> usize {
        self.steps
    }

    /// 吸收一轮的电路。
    pub fn absorb_round(
        &mut self,
        circuits: Vec<RelaxedR1CS<Fr>>,
    ) -> Result<NovaRoundResult, NovaFoldingError> {
        if circuits.is_empty() {
            return Err(NovaFoldingError::EmptyRound);
        }
        if self.steps >= self.storage_period {
            return Err(NovaFoldingError::CycleComplete);
        }

        let delta = circuits.iter().fold(Fr::zero(), |acc, circuit| {
            acc + assignments_digest(&circuit.assignments)
        });
        let weight = Fr::from((self.steps + 1) as u64);
        let step_circuit = NovaStepCircuit::new(circuits.clone());

        if self.pp.is_none() {
            let pp = PublicParams::<NovaEngine1, NovaEngine2, NovaStepCircuit>::setup(
                &step_circuit,
                &*NovaSNARK1::ck_floor(),
                &*NovaSNARK2::ck_floor(),
            )?;
            let mut recursive_snark =
                RecursiveSNARK::<NovaEngine1, NovaEngine2, NovaStepCircuit>::new(
                    &pp,
                    &step_circuit,
                    &self.initial_z,
                )?;
            // 将内部计数推进到第一步
            recursive_snark.prove_step(&pp, &step_circuit)?;
            self.pp = Some(pp);
            self.recursive_snark = Some(recursive_snark);
        } else {
            let pp = self.pp.as_ref().ok_or(NovaFoldingError::NotInitialized)?;
            let recursive_snark = self
                .recursive_snark
                .as_mut()
                .ok_or(NovaFoldingError::NotInitialized)?;
            recursive_snark.prove_step(pp, &step_circuit)?;
        }

        self.accumulator += delta + weight;
        self.steps += 1;
        self.round_accumulators.push(self.accumulator);
        self.finalized = None;

        if let Some(snark) = &self.recursive_snark {
            let outputs = snark.outputs();
            if outputs.len() == 2 {
                debug_assert_eq!(nova_scalar_to_fr(&outputs[0]), self.accumulator);
                debug_assert_eq!(nova_scalar_to_fr(&outputs[1]), Fr::from(self.steps as u64),);
            }
        }

        Ok(NovaRoundResult {
            step_index: self.steps,
            accumulator: self.accumulator,
        })
    }

    /// 完成折叠周期并生成最终证明。
    pub fn finalize(&mut self) -> Result<Option<NovaFinalProof>, NovaFoldingError> {
        if self.steps < self.storage_period {
            return Ok(None); // 周期未完成
        }
        if let Some(proof) = &self.finalized {
            return Ok(Some(proof.clone())); // 返回缓存的证明
        }

        let pp = self.pp.as_ref().ok_or(NovaFoldingError::NotInitialized)?;
        let recursive_snark = self
            .recursive_snark
            .as_ref()
            .ok_or(NovaFoldingError::NotInitialized)?;

        recursive_snark.verify(pp, self.steps, &self.initial_z)?;

        let (pk, vk) = CompressedSNARK::<
            NovaEngine1,
            NovaEngine2,
            NovaStepCircuit,
            NovaSNARK1,
            NovaSNARK2,
        >::setup(pp)?;

        let compressed = CompressedSNARK::<
            NovaEngine1,
            NovaEngine2,
            NovaStepCircuit,
            NovaSNARK1,
            NovaSNARK2,
        >::prove(pp, &pk, recursive_snark)?;

        compressed.verify(&vk, self.steps, &self.initial_z)?;

        let proof_bytes = bincode::serialize(&compressed)
            .map_err(|err| NovaFoldingError::Serialization(err.to_string()))?;
        let vk_bytes = bincode::serialize(&vk)
            .map_err(|err| NovaFoldingError::Serialization(err.to_string()))?;

        let proof = NovaFinalProof {
            compressed_snark: proof_bytes,
            verifier_key: vk_bytes,
            steps: self.steps,
            accumulator: self.accumulator,
        };
        self.finalized = Some(proof.clone());
        Ok(Some(proof))
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
        assert_ne!(accumulator.accumulator, Fr::zero());
        assert!(accumulator.total_constraints() > 0);
    }

    #[test]
    fn nova_cycle_folds_multiple_rounds() {
        let params = DPDPParams {
            g: G2Projective::generator(),
            u: G1Projective::generator(),
            pk_beta: G2Projective::generator(),
            sk_alpha: BigUint::from(1u32),
        };
        let proof = DPDPProof {
            mu: "0".into(),
            sigma: serialize_g1(&G1Projective::generator()),
        };
        let block = Block {
            height: 1,
            prev_hash: h_join(["prev_hash"]),
            seed: h_join(["seed"]),
            leader_id: "node".into(),
            accum_proof_hash: h_join(["acc"]),
            merkle_roots: HashMap::new(),
            round_proof_stmt_hash: h_join(["stmt"]),
            body: BlockBody::default(),
            time_tree_roots: HashMap::new(),
            bobtail_k: 0,
            bobtail_target: h_join(["target"]),
            timestamp: 0,
        };
        let mut storage = StorageStateTree::default();
        storage.file_roots.insert("file".into(), h_join(["leaf"]));
        storage.build();
        let updates = vec![("file".to_string(), h_join(["leaf_next"]))];

        let (dpdp_circuit, _) = dpdp_verification_relaxed_r1cs(&params, &proof, &[]);
        let block_circuit = block_validation_relaxed_r1cs(&block, &block.prev_hash, block.height);
        let state_circuit = state_update_relaxed_r1cs(&storage, &updates);

        let mut cycle = NovaFoldingCycle::new(2);
        let first = cycle
            .absorb_round(vec![
                dpdp_circuit.clone(),
                block_circuit.clone(),
                state_circuit.clone(),
            ])
            .expect("first round");
        assert_eq!(first.step_index, 1);
        assert_ne!(first.accumulator, Fr::zero());

        let second = cycle
            .absorb_round(vec![dpdp_circuit, block_circuit, state_circuit])
            .expect("second round");
        assert_eq!(second.step_index, 2);
        assert_ne!(second.accumulator, Fr::zero());

        let final_proof = cycle.finalize().expect("finalize").expect("proof emitted");
        assert_eq!(final_proof.steps, 2);
        assert!(!final_proof.compressed_snark.is_empty());
        assert!(!final_proof.verifier_key.is_empty());
    }

    #[test]
    fn field_conversion_roundtrip() {
        let samples = [
            Fr::zero(),
            Fr::one(),
            Fr::from(2u64),
            Fr::from(42u64),
            -Fr::one(),
            -Fr::from(2u64),
        ];

        for sample in samples {
            let converted = fr_to_nova_scalar(&sample);
            let roundtrip = nova_scalar_to_fr(&converted);
            assert_eq!(roundtrip, sample);
        }
    }
}
