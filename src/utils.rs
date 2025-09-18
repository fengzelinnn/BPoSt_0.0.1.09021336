use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use indexmap::IndexMap;
use light_poseidon::{Poseidon, PoseidonHasher};
use log::{Level, LevelFilter, Metadata, Record};
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
#[cfg(not(target_family = "wasm"))]
use std::thread;

#[cfg(target_family = "wasm")]
fn create_poseidon_hasher() -> Poseidon<Fr> {
    Poseidon::<Fr>::new_circom(2).expect("failed to initialize Poseidon hasher for 2 inputs")
}

#[cfg(not(target_family = "wasm"))]
fn create_poseidon_hasher() -> Poseidon<Fr> {
    const STACK_SIZE: usize = 4 * 1024 * 1024;
    thread::Builder::new()
        .name("poseidon-init".into())
        .stack_size(STACK_SIZE)
        .spawn(|| {
            Poseidon::<Fr>::new_circom(2)
                .expect("failed to initialize Poseidon hasher for 2 inputs")
        })
        .expect("failed to spawn poseidon initializer")
        .join()
        .expect("poseidon initializer thread panicked")
}

thread_local! {
    static POSEIDON_STATE: RefCell<Poseidon<Fr>> = RefCell::new(create_poseidon_hasher());
}

const BYTES_DOMAIN: &[u8] = b"BPoStPoseidonHashv1";
const HJOIN_DOMAIN: &[u8] = b"HJOINv1";

fn domain_to_field(domain: &[u8]) -> Fr {
    let mut buffer = [0u8; 32];
    let copy_len = domain.len().min(32);
    buffer[32 - copy_len..].copy_from_slice(&domain[..copy_len]);
    Fr::from_be_bytes_mod_order(&buffer)
}

static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static LOGGER_GUARD: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn bytes_to_field_elems(data: &[u8]) -> Vec<Fr> {
    data.chunks(32)
        .map(|chunk| {
            let mut buffer = [0u8; 32];
            let copy_len = chunk.len();
            buffer[32 - copy_len..].copy_from_slice(chunk);
            Fr::from_be_bytes_mod_order(&buffer)
        })
        .collect()
}

fn poseidon_compress(left: Fr, right: Fr) -> Fr {
    POSEIDON_STATE.with(|cell| {
        let mut hasher = cell.borrow_mut();
        hasher
            .hash(&[left, right])
            .expect("poseidon hash with two inputs should succeed")
    })
}

fn poseidon_hash_bytes(data: &[u8]) -> Fr {
    let mut state = domain_to_field(BYTES_DOMAIN);
    let elements = bytes_to_field_elems(data);
    if elements.is_empty() {
        return poseidon_compress(state, Fr::from(0u32));
    }
    for element in elements {
        state = poseidon_compress(state, element);
    }
    state
}

fn field_to_biguint(value: Fr) -> BigUint {
    let bytes = value.into_bigint().to_bytes_be();
    BigUint::from_bytes_be(&bytes)
}

fn field_to_bytes(value: Fr) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

pub fn hash_to_field(data: &[u8]) -> BigUint {
    field_to_biguint(poseidon_hash_bytes(data))
}

pub fn snark_hash_bytes(data: &[u8]) -> [u8; 32] {
    field_to_bytes(poseidon_hash_bytes(data))
}

pub fn snark_hash_hex(data: &[u8]) -> String {
    hex::encode(snark_hash_bytes(data))
}

pub fn h_join<I, S>(parts: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut state = domain_to_field(HJOIN_DOMAIN);
    let mut has_parts = false;
    for part in parts {
        has_parts = true;
        let piece = poseidon_hash_bytes(part.as_ref().as_bytes());
        state = poseidon_compress(state, piece);
    }
    if !has_parts {
        state = poseidon_compress(state, Fr::from(0u32));
    }
    hex::encode(field_to_bytes(state))
}

pub fn sha256_hex(data: &[u8]) -> String {
    snark_hash_hex(data)
}

/// 使用 CPU 并行批量计算 Poseidon 哈希（输出 hex）
pub fn cpu_poseidon_hash_hex_batch(inputs: &[Vec<u8>]) -> Vec<String> {
    const CHUNK: usize = 256;
    if inputs.len() <= CHUNK {
        return inputs.iter().map(|bytes| snark_hash_hex(bytes)).collect();
    }

    use rayon::prelude::*;

    // Process hashes in fixed-size chunks so Rayon does not recurse too deeply on
    // the caller's stack. On some platforms with smaller default stacks the
    // previous fully recursive `par_iter()` based approach could overflow when
    // the miner evaluated large nonce batches.
    let mut outputs = vec![String::new(); inputs.len()];
    outputs
        .par_chunks_mut(CHUNK)
        .enumerate()
        .for_each(|(idx, chunk)| {
            let start = idx * CHUNK;
            let slice = &inputs[start..start + chunk.len()];
            for (slot, data) in chunk.iter_mut().zip(slice.iter()) {
                *slot = snark_hash_hex(data);
            }
        });
    outputs
}

/// 预留 GPU 批量哈希入口：启用 gpu-icicle 特性时尝试走 GPU；不可用时返回 None
pub fn try_gpu_poseidon_hash_hex_batch(_inputs: &[Vec<u8>]) -> Option<Vec<String>> {
    #[cfg(feature = "gpu-icicle")]
    {
        // 这里预留与 icicle/cuda 集成点：
        // - 实际工程中可将 _inputs 编码为 field elements，然后调用 GPU kernel 批量计算 Poseidon。
        // - 当前实现暂不提供内核，返回 None 以触发安全回退至 CPU 并行版本。
        return None;
    }
    #[allow(unreachable_code)]
    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleBuild {
    pub root: String,
    pub nodes: HashMap<String, Vec<String>>,
}

pub fn build_merkle_root(mut leaf_hashes: Vec<String>) -> String {
    if leaf_hashes.is_empty() {
        return sha256_hex(b"");
    }
    if leaf_hashes.len() == 1 {
        return leaf_hashes[0].clone();
    }
    if leaf_hashes.len() % 2 == 1 {
        if let Some(last) = leaf_hashes.last().cloned() {
            leaf_hashes.push(last);
        }
    }
    let mut next_level = Vec::new();
    for pair in leaf_hashes.chunks(2) {
        let mut sorted = pair.to_vec();
        sorted.sort();
        let combined = h_join(&[&sorted[0], &sorted[1]]);
        next_level.push(combined);
    }
    build_merkle_root(next_level)
}

pub fn build_merkle_tree(leaf_hashes: &[String]) -> (String, IndexMap<String, Vec<String>>) {
    if leaf_hashes.is_empty() {
        return (sha256_hex(b""), IndexMap::new());
    }
    if leaf_hashes.len() == 1 {
        return (leaf_hashes[0].clone(), IndexMap::new());
    }
    let mut nodes: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut level: Vec<String> = leaf_hashes.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            if let Some(last) = level.last().cloned() {
                level.push(last);
            }
        }
        let mut next_level = Vec::new();
        for pair in level.chunks(2) {
            let (a, b) = (&pair[0], &pair[1]);
            let mut sorted = vec![a.clone(), b.clone()];
            sorted.sort();
            let parent = h_join(&[&sorted[0], &sorted[1]]);
            nodes.insert(parent.clone(), sorted.clone());
            next_level.push(parent);
        }
        level = next_level;
    }
    (level[0].clone(), nodes)
}

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: SimpleLogger = SimpleLogger;

pub fn init_logging() {
    if LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }
    let _guard = LOGGER_GUARD.lock();
    if !LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        log::set_logger(&LOGGER).expect("logger already set");
        log::set_max_level(LevelFilter::Debug);
        LOGGER_INITIALIZED.store(true, Ordering::SeqCst);
    }
}

fn to_level(level: &str) -> Level {
    match level.to_ascii_uppercase().as_str() {
        "DEBUG" => Level::Debug,
        "WARN" | "WARNING" => Level::Warn,
        "ERROR" => Level::Error,
        "CRITICAL" => Level::Error,
        "TRACE" => Level::Trace,
        _ => Level::Info,
    }
}

pub fn log_msg(level: &str, actor_type: &str, actor_id: impl Into<Option<String>>, msg: &str) {
    init_logging();
    let id_opt = actor_id.into();
    let who = if let Some(id) = id_opt {
        format!("{}({})", actor_type, id)
    } else {
        actor_type.to_string()
    };
    let level = to_level(level);
    log::log!(level, "{}: {}", who, msg);
}

pub fn random_hex_string(len: usize) -> String {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut rng = rand::thread_rng();
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let idx = rng.gen_range(0..HEX_CHARS.len());
        s.push(char::from(HEX_CHARS[idx]));
    }
    s
}

pub fn format_bytes_hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        write!(&mut s, "{:02x}", b).expect("write to string");
    }
    s
}
