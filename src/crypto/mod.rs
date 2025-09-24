pub mod dpdp;
pub mod folding;

use ark_bn254::{Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use num_bigint::BigUint;

/// BN254 曲线的阶，以十进制字符串表示。
pub const CURVE_ORDER_STR: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// 解析曲线阶为 `BigUint`，便于与随机标量进行模运算。
pub fn curve_order() -> BigUint {
    BigUint::parse_bytes(CURVE_ORDER_STR.as_bytes(), 10).expect("invalid curve order")
}

/// 将有限域元素序列化为大端字节序。
fn fq_to_bytes(f: &Fq) -> [u8; 32] {
    let bigint = f.into_bigint();
    let mut bytes = bigint.to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// BN254 Fq2 元素的序列化助手。
fn fq2_to_bytes(f: &Fq2) -> [u8; 64] {
    let mut out = [0u8; 64];
    let c0 = fq_to_bytes(&f.c0);
    let c1 = fq_to_bytes(&f.c1);
    out[..32].copy_from_slice(&c0);
    out[32..].copy_from_slice(&c1);
    out
}

/// 将 G1 群元素编码为 96 字节的非压缩表示。
pub fn serialize_g1(point: &G1Projective) -> Vec<u8> {
    if point.is_zero() {
        return vec![0u8; 96];
    }
    let affine = point.into_affine();
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&fq_to_bytes(&affine.x));
    out.extend_from_slice(&fq_to_bytes(&affine.y));
    out.extend_from_slice(&fq_to_bytes(&Fq::one()));
    out
}

/// 从 96 字节的非压缩表示恢复 G1 群元素。
pub fn deserialize_g1(bytes: &[u8]) -> G1Projective {
    if bytes.len() != 96 {
        panic!("G1 serialization must be 96 bytes");
    }
    if bytes.iter().all(|&b| b == 0) {
        return G1Projective::zero();
    }
    let x = Fq::from_be_bytes_mod_order(&bytes[0..32]);
    let y = Fq::from_be_bytes_mod_order(&bytes[32..64]);
    let affine = G1Affine::new(x, y);
    affine.into()
}

/// 将 G2 群元素编码为 192 字节的非压缩表示。
pub fn serialize_g2(point: &G2Projective) -> Vec<u8> {
    if point.is_zero() {
        return vec![0u8; 192];
    }
    let affine = point.into_affine();
    let mut out = Vec::with_capacity(192);
    out.extend_from_slice(&fq2_to_bytes(&affine.x));
    out.extend_from_slice(&fq2_to_bytes(&affine.y));
    out.extend_from_slice(&fq2_to_bytes(&Fq2::one()));
    out
}

/// 从 192 字节的非压缩表示恢复 G2 群元素。
pub fn deserialize_g2(bytes: &[u8]) -> G2Projective {
    if bytes.len() != 192 {
        panic!("G2 serialization must be 192 bytes");
    }
    if bytes.iter().all(|&b| b == 0) {
        return G2Projective::zero();
    }
    let x0 = Fq::from_be_bytes_mod_order(&bytes[0..32]);
    let x1 = Fq::from_be_bytes_mod_order(&bytes[32..64]);
    let y0 = Fq::from_be_bytes_mod_order(&bytes[64..96]);
    let y1 = Fq::from_be_bytes_mod_order(&bytes[96..128]);
    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);
    let affine = G2Affine::new(x, y);
    affine.into()
}
