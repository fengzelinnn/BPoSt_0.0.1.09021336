use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Local;

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
use std::fs::OpenOptions;
use std::path::PathBuf;
#[cfg(not(target_family = "wasm"))]
use std::thread;

use crossbeam_channel::{bounded, Receiver, Sender};

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
fn resolve_log_path() -> PathBuf {
    if let Ok(path) = std::env::var("BPST_LOG_PATH") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("BPOST_LOG_PATH") {
        // 兼容旧的环境变量名称
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bpst.log")
}

static LOG_FILE: Lazy<Mutex<std::fs::File>> = Lazy::new(|| {
    let path = resolve_log_path();
    if let Some(parent) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            panic!(
                "failed to create log directory {}: {}",
                parent.display(),
                err
            );
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap_or_else(|err| panic!("failed to open log file {}: {}", path.display(), err));
    Mutex::new(file)
});

struct CpuLimiter {
    sender: Sender<()>,
    receiver: Receiver<()>,
}

impl CpuLimiter {
    fn new(max_permits: usize) -> Self {
        assert!(max_permits > 0, "CPU limiter requires at least one permit");
        let (sender, receiver) = bounded(max_permits);
        for _ in 0..max_permits {
            sender.send(()).expect("failed to seed CPU limiter permits");
        }
        Self { sender, receiver }
    }

    fn acquire(&self) -> CpuPermit {
        self.receiver
            .recv()
            .expect("CPU limiter channel unexpectedly closed");
        CpuPermit {
            sender: self.sender.clone(),
        }
    }

    fn run<F, R>(&self, task: F) -> R
    where
        F: FnOnce() -> R,
    {
        let permit = self.acquire();
        let result = task();
        drop(permit);
        result
    }
}

struct CpuPermit {
    sender: Sender<()>,
}

impl Drop for CpuPermit {
    fn drop(&mut self) {
        let _ = self.sender.send(());
    }
}

fn heavy_cpu_parallelism() -> usize {
    let detected = std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(1);
    detected.saturating_sub(1).max(1)
}

static HEAVY_CPU_LIMITER: Lazy<CpuLimiter> = Lazy::new(|| CpuLimiter::new(heavy_cpu_parallelism()));

/// Execute a CPU-intensive task while respecting the global concurrency limit.
pub fn with_cpu_heavy_limit<F, R>(task: F) -> R
where
    F: FnOnce() -> R,
{
    HEAVY_CPU_LIMITER.run(task)
}

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

/// 预留的 GPU 批量哈希入口。
///
/// 早期版本尝试通过可选的 `gpu-icicle` 特性调用 CUDA 库，但在没有 GPU 的开发环境中
/// 会导致编译失败。为了保持项目的可移植性，我们直接返回 `None`，提醒调用方回退到
/// CPU 版本。未来如果需要重新引入 GPU 支持，可以在不影响主流程的情况下填充这里的
/// 实现。
pub fn try_gpu_poseidon_hash_hex_batch(_inputs: &[Vec<u8>]) -> Option<Vec<String>> {
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
        let combined = h_join([&sorted[0], &sorted[1]]);
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
            let parent = h_join([&sorted[0], &sorted[1]]);
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
            let timestamp = Local::now();
            let module = record.module_path().unwrap_or_else(|| record.target());
            let file = record.file().unwrap_or("unknown");
            let line = record
                .line()
                .map(|line| line.to_string())
                .unwrap_or_else(|| String::from("-"));
            let thread = std::thread::current();
            let thread_name = thread.name().unwrap_or("unnamed");
            let thread_id = format!("{:?}", thread.id());
            let formatted = format!(
                "{} {:<5} [{}:{}:{}] [thread {} {}] - {}",
                timestamp.format("%Y-%m-%d %H:%M:%S%.6f"),
                record.level(),
                module,
                file,
                line,
                thread_name,
                thread_id,
                record.args()
            );
            println!("{}", formatted);
            let mut file = LOG_FILE.lock();
            let _ = writeln!(&mut *file, "{}", formatted);
            let _ = file.flush();
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
        Lazy::force(&LOG_FILE);
        log::set_logger(&LOGGER).expect("logger already set");
        log::set_max_level(LevelFilter::Trace);
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
