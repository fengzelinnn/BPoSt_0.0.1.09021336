// 导入标准库的 HashMap 用于存储键值对
use std::collections::HashMap;

// 导入项目内的数据结构 BobtailProof
use crate::common::datastructures::BobtailProof;
// 导入项目内的工具函数，包括 CPU 和 GPU 上的 Poseidon 哈希实现
use crate::utils::{cpu_poseidon_hash_hex_batch, try_gpu_poseidon_hash_hex_batch};

/// Miner 结构体定义了矿工的角色
/// 矿工负责通过“挖矿”来创建 Bobtail 证明，这是参与共识的关键步骤
pub struct Miner {
    // 矿工所属节点的 ID
    pub node_id: String,
    // 接收挖矿奖励的地址
    pub reward_address: String,
}

impl Miner {
    /// 创建一个新的 Miner 实例
    pub fn new(node_id: String, reward_address: String) -> Self {
        Self {
            node_id,
            reward_address,
        }
    }

    /// 执行挖矿操作，尝试找到一个符合条件的 Bobtail 证明
    /// 挖矿的本质是寻找一个 nonce（随机数），使得组合了各种信息后的哈希值最小
    pub fn mine(
        &self,
        seed: &str, // 挖矿种子，通常来自前一个区块的哈希，确保不可预测性
        storage_root: &str, // 矿工存储根哈希，证明其存储状态
        file_roots: &HashMap<String, String>, // 存储的各个文件的根哈希
        num_files: usize, // 存储的文件数量
        max_nonce: u64, // 要尝试的最大 nonce 值，限制了单次挖矿的计算量
    ) -> Vec<BobtailProof> {
        // 初始化找到的最佳哈希和对应的 nonce
        let mut best_hash = String::new();
        let mut best_nonce: Option<u64> = None;

        if max_nonce == 0 {
            return Vec::new(); // 如果不尝试任何 nonce，直接返回空
        }

        // 为了提高效率，挖矿过程是分批处理的
        // 选择一个适中的批大小，以兼顾哈希吞吐量和内存占用
        let chunk_size: u64 = 65_536; // 每一批尝试 65536 个 nonce
        let mut start: u64 = 0;
        while start < max_nonce {
            let end = (start + chunk_size).min(max_nonce);
            let len = (end - start) as usize;

            // 预先构造好这一批要进行哈希计算的所有输入数据
            // 这样做可以避免在哈希计算的循环中频繁进行字符串格式化和内存分配
            let inputs: Vec<Vec<u8>> = (0..len)
                .map(|i| {
                    let nonce = start + i as u64;
                    // 哈希的输入内容包含了种子、存储根、节点ID和 nonce
                    // 这是为了确保每个矿工在每个时刻的计算都是独特的
                    format!(
                        "bobtail|{}|{}|{}|{}",
                        seed, storage_root, self.node_id, nonce
                    )
                    .into_bytes()
                })
                .collect();

            // 核心的哈希计算步骤
            // 优先尝试使用 GPU 进行批量 Poseidon 哈希，因为 GPU 并行计算能力更强，速度更快
            // 如果 GPU 不可用或失败 (例如没有安装 CUDA 或 GPU 驱动)，则回退到使用 CPU 进行并行批量哈希
            let hashes: Vec<String> = if let Some(hs) = try_gpu_poseidon_hash_hex_batch(&inputs) {
                hs
            } else {
                cpu_poseidon_hash_hex_batch(&inputs)
            };

            // 遍历本批计算出的哈希结果，更新全局找到的最优解
            for (i, h) in hashes.into_iter().enumerate() {
                let nonce = start + i as u64;
                // "最优"在这里意味着哈希值（按字典序）最小
                if best_hash.is_empty() || h < best_hash {
                    best_hash = h;
                    best_nonce = Some(nonce);
                }
            }

            start = end; // 移动到下一批
        }

        // 如果在所有尝试后找到了一个 nonce，就用它来构建 Bobtail 证明
        let Some(nonce) = best_nonce else {
            return Vec::new(); // 没找到，返回空
        };
        
        // 返回找到的唯一最佳证明
        vec![BobtailProof {
            node_id: self.node_id.clone(),
            address: self.reward_address.clone(),
            root: storage_root.to_string(),
            file_roots: file_roots.clone(),
            nonce: nonce.to_string(),
            proof_hash: best_hash, // 挖矿的目标，即找到的最小哈希
            lots: num_files.max(1).to_string(), // "lots" 类似于权重，与存储文件数量相关
        }]
    }
}
