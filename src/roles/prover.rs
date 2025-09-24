// 导入标准库的 HashMap
use std::collections::HashMap;

// 导入大整数库
use num_bigint::BigUint;

// 导入项目内的数据结构和密码学模块
use crate::common::datastructures::{DPDPProof, DPDPTags};
use crate::crypto::dpdp::DPDP;
use crate::utils::log_msg;

/// dPDP 挑战向量类型别名，元素为 (块索引, 挑战系数)。
pub type ChallengeVector = Vec<(usize, BigUint)>;

/// 每个挑战对应的贡献值，包含块索引、加权系数和缩放后的标签。
pub type ContributionVector = Vec<(usize, BigUint, Vec<u8>)>;

/// Prover 结构体定义了证明者的角色
/// 证明者的核心职责是响应 dPDP（动态可证明数据拥有权）挑战，
/// 生成一个密码学证明，以证实自己确实存储了特定的文件数据。
pub struct Prover {
    // 证明者所属节点的 ID
    pub node_id: String,
}

impl Prover {
    /// 创建一个新的 Prover 实例
    pub fn new(node_id: String) -> Self {
        Self { node_id }
    }

    /// 为给定的文件生成 dPDP 证明
    ///
    /// # Arguments
    /// * `file_id` - 正在为其生成证明的文件的 ID
    /// * `file_chunks` - 文件的实际数据块内容
    /// * `file_tags` - 文件的 dPDP 标签，这是预先计算好的用于生成证明的元数据
    /// * `prev_hash` - 上一个区块的哈希，用作生成挑战的盐，确保挑战的不可预测性
    /// * `timestamp` - 时间戳，同样用于生成挑战
    /// * `challenge_size` - 可选参数，指定挑战中要抽样的块的数量
    ///
    /// # Returns
    /// 一个元组，包含：
    /// * `DPDPProof` - 生成的聚合 dPDP 证明
    /// * `Vec<(usize, BigUint)>` - 生成的挑战，格式为 (索引, 随机值) 的列表
    /// * `Vec<(usize, BigUint, Vec<u8>)>` - 未聚合的贡献值，用于更新文件的状态（例如时间戳或版本）
    pub fn prove(
        &self,
        file_id: &str,
        file_chunks: &HashMap<usize, Vec<u8>>,
        file_tags: &DPDPTags,
        prev_hash: &str,
        timestamp: u64,
        challenge_size: Option<usize>,
    ) -> (DPDPProof, ChallengeVector, ContributionVector) {
        // 1. 根据上下文（前一个块哈希、时间戳）和文件标签生成一个确定性的随机挑战
        let challenge = DPDP::gen_chal(prev_hash, timestamp, file_tags, challenge_size);

        // 2. 使用文件块、标签和挑战来生成聚合的 dPDP 证明
        let proof = DPDP::gen_proof(file_tags, file_chunks, &challenge);

        // 3. 生成用于更新文件状态的“贡献值”
        // 这些值是证明过程的副产品，但对于维护文件的版本和状态至关重要
        let contributions = DPDP::gen_contributions(file_tags, file_chunks, &challenge);

        log_msg(
            "DEBUG",
            "dPDP",
            Some(self.node_id.clone()),
            &format!("为文件 {} 生成了dPDP证明与未聚合贡献", file_id),
        );

        // 返回证明、挑战和贡献值
        (proof, challenge, contributions)
    }
}
