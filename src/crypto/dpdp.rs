use std::collections::HashMap;

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, PrimeGroup};
use ark_ff::{PrimeField, Zero};
use num_bigint::{BigUint, ToBigUint};
use num_traits::cast::ToPrimitive;
use rand::RngCore;

use crate::common::datastructures::{DPDPParams, DPDPProof, DPDPTags};
use crate::crypto::folding::{dpdp_verification_relaxed_r1cs, RelaxedR1CS};
use crate::crypto::{curve_order, deserialize_g1, serialize_g1};
use crate::merkle::MerkleTree;
use crate::utils::{hash_to_field, sha256_hex};

/// Merkle 证明路径，按从叶子到根的顺序存储相邻节点及其方向。
pub type MerkleProofPath = Vec<(String, char)>;

/// 挑战索引到数据块与 Merkle 证明的映射。
pub type ChallengedChunkData = HashMap<usize, (Vec<u8>, MerkleProofPath)>;

/// 将任意消息哈希到 BN254 G1 群，作为 dPDP 中的基点。
pub fn hash_to_g1(message: &[u8]) -> G1Projective {
    let field_elem = hash_to_field(message);
    let mut bytes = field_elem.to_bytes_be();
    if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    let scalar = Fr::from_be_bytes_mod_order(&bytes);
    let mut point: G1Projective = G1Affine::generator().into();
    point = point.mul_bigint(scalar.into_bigint());
    if point.is_zero() {
        point = G1Affine::generator().into();
    }
    point
}

/// 生成非零随机标量，用于模拟私钥或挑战系数。
fn random_scalar() -> BigUint {
    let order = curve_order();
    let mut rng = rand::thread_rng();
    loop {
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let candidate = BigUint::from_bytes_be(&buf) % &order;
        if !candidate.is_zero() {
            return candidate;
        }
    }
}

/// 将 `BigUint` 裁剪到曲线阶范围内并转换为 `Fr` 元素。
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

/// 将原始数据块映射到大整数，供 dPDP 计算使用。
fn chunk_to_int(chunk: &[u8]) -> BigUint {
    let h = sha256_hex(chunk);
    BigUint::parse_bytes(h.as_bytes(), 16).unwrap_or_default()
}

/// dPDP 协议的高阶接口封装。
pub struct DPDP;

#[derive(Debug, Clone)]
pub struct DPDPVerificationOutput {
    /// 证明是否通过验证。
    pub valid: bool,
    /// 供 Nova 折叠器继续递归的松弛 R1CS 描述。
    pub circuit: RelaxedR1CS<Fr>,
}

impl DPDP {
    /// 生成 dPDP 公私钥参数。
    pub fn key_gen() -> DPDPParams {
        let sk_alpha = random_scalar();
        let g: G2Projective = G2Affine::generator().into();
        let u: G1Projective = G1Affine::generator().into();
        let sk_fr = biguint_to_fr(&sk_alpha);
        let pk_beta = g.mul_bigint(sk_fr.into_bigint());
        DPDPParams {
            g,
            u,
            pk_beta,
            sk_alpha,
        }
    }

    /// 使用 dPDP 私钥为文件块生成标签。
    pub fn tag_file(params: &DPDPParams, file_chunks: &[Vec<u8>]) -> DPDPTags {
        let mut tags_bytes = Vec::with_capacity(file_chunks.len());
        let sk_fr = biguint_to_fr(&params.sk_alpha);
        for (i, chunk) in file_chunks.iter().enumerate() {
            let mut b_i = chunk_to_int(chunk);
            let order = curve_order();
            b_i %= &order;
            let h_i = hash_to_g1(i.to_string().as_bytes());
            let term2 = params.u.mul_bigint(biguint_to_fr(&b_i).into_bigint());
            let base = h_i + term2;
            let sigma = base.mul_bigint(sk_fr.into_bigint());
            tags_bytes.push(serialize_g1(&sigma));
        }
        DPDPTags { tags: tags_bytes }
    }

    /// 根据链上状态生成挑战向量。
    pub fn gen_chal(
        prev_hash: &str,
        timestamp: u64,
        tags: &DPDPTags,
        m: Option<usize>,
    ) -> Vec<(usize, BigUint)> {
        if tags.is_empty() {
            return Vec::new();
        }
        let n = tags.tags.len();
        let count = if let Some(m) = m {
            m
        } else {
            let mut base = (timestamp as usize) % n;
            if base == 0 {
                base = 5;
            }
            base = base.max(1);
            base
        };
        let order = curve_order();
        let mut challenges = Vec::new();
        for j in 0..count {
            let seed = format!("{}:{}:{}", prev_hash, timestamp, j);
            let idx = (hash_to_field(seed.as_bytes()) % n.to_biguint().unwrap())
                .to_usize()
                .unwrap_or(0)
                % n;
            let value_seed = format!("chal|{}", seed);
            let v_i = hash_to_field(value_seed.as_bytes()) % &order;
            challenges.push((idx, v_i));
        }
        challenges
    }

    /// 针对挑战向量计算每个数据块的贡献值。
    pub fn gen_contributions(
        tags: &DPDPTags,
        file_chunks: &HashMap<usize, Vec<u8>>,
        challenge: &[(usize, BigUint)],
    ) -> Vec<(usize, BigUint, Vec<u8>)> {
        let order = curve_order();
        let mut contributions = Vec::new();
        for (i, v_i) in challenge {
            let chunk = file_chunks
                .get(i)
                .expect("missing chunk for challenge index");
            let mut b_i = chunk_to_int(chunk);
            b_i %= &order;
            let tag_bytes = tags.tags.get(*i).expect("missing tag for challenge index");
            let sigma_i = deserialize_g1(tag_bytes);
            let mu_i = (v_i * &b_i) % &order;
            let sigma_scaled = sigma_i.mul_bigint(biguint_to_fr(v_i).into_bigint());
            contributions.push((*i, mu_i, serialize_g1(&sigma_scaled)));
        }
        contributions
    }

    /// 聚合挑战，生成完整的 dPDP 证明。
    pub fn gen_proof(
        tags: &DPDPTags,
        file_chunks: &HashMap<usize, Vec<u8>>,
        challenge: &[(usize, BigUint)],
    ) -> DPDPProof {
        let order = curve_order();
        let mut agg_mu = BigUint::from(0u32);
        let mut agg_sigma = G1Projective::zero();
        for (i, v_i) in challenge {
            let chunk = file_chunks.get(i).expect("missing chunk");
            let mut b_i = chunk_to_int(chunk);
            b_i %= &order;
            let tag_bytes = tags.tags.get(*i).expect("missing tag");
            let sigma_i = deserialize_g1(tag_bytes);
            agg_mu = (agg_mu + (v_i * &b_i)) % &order;
            agg_sigma += sigma_i.mul_bigint(biguint_to_fr(v_i).into_bigint());
        }
        DPDPProof {
            mu: agg_mu.to_string(),
            sigma: serialize_g1(&agg_sigma),
        }
    }

    /// 仅检查证明是否有效。
    pub fn check_proof(
        params: &DPDPParams,
        proof: &DPDPProof,
        challenge: &[(usize, BigUint)],
    ) -> bool {
        Self::check_proof_with_relaxed(params, proof, challenge).valid
    }

    /// 返回验证结果及对应的松弛 R1CS 实例。
    pub fn check_proof_with_relaxed(
        params: &DPDPParams,
        proof: &DPDPProof,
        challenge: &[(usize, BigUint)],
    ) -> DPDPVerificationOutput {
        let sigma = deserialize_g1(&proof.sigma);
        if sigma.is_zero() {
            let (circuit, _) = dpdp_verification_relaxed_r1cs(params, proof, challenge);
            return DPDPVerificationOutput {
                valid: challenge.is_empty(),
                circuit,
            };
        }

        let (circuit, valid) = dpdp_verification_relaxed_r1cs(params, proof, challenge);
        DPDPVerificationOutput { valid, circuit }
    }

    /// 验证带有 Merkle 证明的 dPDP 响应。
    pub fn verify_with_merkle(
        params: &DPDPParams,
        proof: &DPDPProof,
        challenge: &[(usize, BigUint)],
        challenged_data: &ChallengedChunkData,
        merkle_root: &str,
    ) -> bool {
        let order = curve_order();
        let mut recomputed_mu = BigUint::from(0u32);
        if challenge.len() != challenged_data.len() {
            return false;
        }
        for (i, v_i) in challenge {
            let Some((chunk, proof_path)) = challenged_data.get(i) else {
                return false;
            };
            let leaf = sha256_hex(chunk);
            if !MerkleTree::verify(&leaf, *i, proof_path, merkle_root) {
                return false;
            }
            let mut b_i = chunk_to_int(chunk);
            b_i %= &order;
            recomputed_mu = (recomputed_mu + v_i * &b_i) % &order;
        }
        let mu_big = BigUint::parse_bytes(proof.mu.as_bytes(), 10).unwrap_or_default();
        if mu_big != recomputed_mu {
            return false;
        }
        Self::check_proof(params, proof, challenge)
    }
}
