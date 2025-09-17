use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

use indexmap::IndexMap;
use log::{Level, LevelFilter, Metadata, Record};
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const FIELD_PRIME_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const MIMC_ROUNDS: usize = 91;

static FIELD_PRIME: Lazy<BigUint> = Lazy::new(|| {
    BigUint::parse_bytes(FIELD_PRIME_DEC.as_bytes(), 10).expect("invalid field prime")
});

static MIMC_CONSTANTS: Lazy<Vec<BigUint>> = Lazy::new(|| {
    let mut consts = Vec::with_capacity(MIMC_ROUNDS);
    let mut seed = b"MIMC7_BN254_CONST".to_vec();
    for i in 0..MIMC_ROUNDS {
        let mut input = seed.clone();
        input.extend_from_slice(&(i as u32).to_be_bytes());
        seed = Sha256::digest(&input).to_vec();
        let mut val = BigUint::from_bytes_be(&seed);
        val %= &*FIELD_PRIME;
        consts.push(val);
    }
    consts
});

static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static LOGGER_GUARD: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn mimc7_permute(mut x: BigUint, k: &BigUint) -> BigUint {
    let p = &*FIELD_PRIME;
    x %= p;
    let key = k.clone() % p;
    for i in 0..MIMC_ROUNDS.saturating_sub(1) {
        let mut t = (&x + &key + &MIMC_CONSTANTS[i]) % p;
        t = t.modpow(&BigUint::from(7u32), p);
        x = t;
    }
    // last round + key
    let mut t = (&x + &key + &MIMC_CONSTANTS[MIMC_ROUNDS - 1]) % p;
    t = t.modpow(&BigUint::from(7u32), p);
    x = (t + key) % p;
    x
}

fn bytes_to_field_elems(data: &[u8]) -> Vec<BigUint> {
    if data.is_empty() {
        return vec![BigUint::from(0u32)];
    }
    let mut elems = Vec::new();
    for chunk in data.chunks(31) {
        let mut val = BigUint::from_bytes_be(chunk);
        val %= &*FIELD_PRIME;
        elems.push(val);
    }
    elems
}

pub fn hash_to_field(data: &[u8]) -> BigUint {
    let mut state = BigUint::from(0u32);
    for m in bytes_to_field_elems(data) {
        let tmp = (state + m) % &*FIELD_PRIME;
        state = mimc7_permute(tmp, &BigUint::from(0u32));
    }
    state % &*FIELD_PRIME
}

pub fn snark_hash_bytes(data: &[u8]) -> [u8; 32] {
    let h = hash_to_field(data);
    let mut bytes = h.to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

pub fn snark_hash_hex(data: &[u8]) -> String {
    hex::encode(snark_hash_bytes(data))
}

pub fn h_join<I, S>(parts: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut state = hash_to_field(b"HJOINv1");
    for part in parts {
        let piece = hash_to_field(part.as_ref().as_bytes());
        let tmp = (state + piece) % &*FIELD_PRIME;
        state = mimc7_permute(tmp, &BigUint::from(0u32));
    }
    let mut bytes = state.to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    hex::encode(bytes)
}

pub fn sha256_hex(data: &[u8]) -> String {
    snark_hash_hex(data)
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
