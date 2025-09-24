use std::collections::HashMap;

use indexmap::IndexMap;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::utils::h_join;

/// 链上共识与存储子系统共享的数据结构定义。
///
/// 这些类型在多个模块之间频繁传递，因此集中在一个文件中便于统一维护和添加文档。
/// 证明摘要，用于在区块中引用节点提交的 Bobtail 证明。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSummary {
    /// 证明提交节点的身份标识。
    pub node_id: String,
    /// 证明的 Poseidon 哈希值。
    pub proof_hash: String,
}

/// 单个挑战条目，包含被挑战的块索引以及挑战系数。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeEntry(pub usize, pub String);

/// 区块主体，记录在一个出块周期内收集到的证明与挑战信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBody {
    /// 领导者选择出的 `k` 个最优 Bobtail 证明。
    #[serde(default)]
    pub selected_k_proofs: Vec<ProofSummary>,
    /// 奖励拆分信息，`account -> amount`。
    #[serde(default)]
    pub coinbase_splits: HashMap<String, String>,
    /// Bobtail 证明集合的 Merkle 树（节点 -> 子节点列表）。
    #[serde(default)]
    pub proofs_merkle_tree: IndexMap<String, Vec<String>>,
    /// dPDP 挑战集合，`file_id -> round -> challenge entries`。
    #[serde(default)]
    pub dpdp_challenges: HashMap<String, HashMap<String, Vec<ChallengeEntry>>>,
    /// dPDP 证明集合，结构与挑战相似。
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

/// 区块头与主体的组合，代表链上的一块数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// 当前区块高度。
    pub height: u64,
    /// 父区块哈希。
    pub prev_hash: String,
    /// Bobtail 随机数种子。
    pub seed: String,
    /// 本轮领导者节点标识。
    pub leader_id: String,
    /// 累计折叠证明的哈希。
    pub accum_proof_hash: String,
    /// 各类 Merkle 树的根。
    pub merkle_roots: HashMap<String, String>,
    /// 折叠证明语句的哈希。
    pub round_proof_stmt_hash: String,
    /// 区块主体。
    pub body: BlockBody,
    /// 时间状态树根，按文件划分。
    #[serde(default)]
    pub time_tree_roots: HashMap<String, HashMap<String, String>>,
    /// Bobtail 算法参数 `k`。
    pub bobtail_k: u64,
    /// 目标难度。
    pub bobtail_target: String,
    /// 区块时间戳。
    pub timestamp: u128,
}

impl Block {
    /// 生成区块头部哈希，作为区块在网络中的唯一标识。
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

/// 单个数据块及其 dPDP 标签，用户节点会将其分发给存储节点。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    /// 数据块在文件中的索引。
    pub index: usize,
    /// 原始数据内容。
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// dPDP 认证标签。
    #[serde(with = "serde_bytes")]
    pub tag: Vec<u8>,
    /// 所属文件的标识。
    pub file_id: String,
}

/// Bobtail 共识中节点提交的证明。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BobtailProof {
    /// 证明提交者节点 ID。
    pub node_id: String,
    /// 节点的网络地址。
    pub address: String,
    /// 当前挖矿窗口的 Merkle 根。
    pub root: String,
    /// 随机数 nonce。
    pub nonce: String,
    /// 证明哈希，用于快速比较。
    pub proof_hash: String,
    /// Bobtail “票数”字段。
    pub lots: String,
    /// （可选）附带的文件 Merkle 根。
    #[serde(default)]
    pub file_roots: HashMap<String, String>,
}

/// dPDP 所需的公开参数与私钥。
#[derive(Debug, Clone)]
pub struct DPDPParams {
    /// 群生成元 `g`（G2）。
    pub g: ark_bn254::G2Projective,
    /// 群生成元 `u`（G1）。
    pub u: ark_bn254::G1Projective,
    /// 公钥 `β`。
    pub pk_beta: ark_bn254::G2Projective,
    /// 私钥 `α`。
    pub sk_alpha: BigUint,
}

/// 文件的 dPDP 标签集合。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPDPTags {
    /// 每个数据块对应的签名标签。
    pub tags: Vec<Vec<u8>>,
}

impl DPDPTags {
    /// 标签数量，即文件块数量。
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// 判断是否为空文件。
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

/// 聚合后的 dPDP 响应，由存储节点返回给验证者。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPDPProof {
    /// 挑战权重的线性组合结果。
    pub mu: String,
    /// 聚合后的签名。
    #[serde(with = "serde_bytes")]
    pub sigma: Vec<u8>,
}
