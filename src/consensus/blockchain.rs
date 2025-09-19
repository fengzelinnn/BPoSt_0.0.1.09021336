// 导入项目内的数据结构 Block 和工具函数 h_join
use crate::common::datastructures::Block;
use crate::utils::h_join;

/// 折叠证明结构体，用于累积和压缩证明
/// 在这个项目中，它被用作一个累加器，将每一轮的证明“折叠”到一个哈希值中
#[derive(Debug, Clone)]
pub struct FoldingProof {
    // 累积的哈希值
    pub acc_hash: String,
}

/// 为折叠证明实现 Default trait，提供一个默认的初始状态
impl Default for FoldingProof {
    fn default() -> Self {
        Self {
            // 初始累加器哈希值
            acc_hash: h_join(["init_acc"]),
        }
    }
}

impl FoldingProof {
    /// 将当前的折叠证明与另一个折叠证明进行“折叠”
    /// 这是一种将新信息（other）合并到现有累加器（self）中的方式
    pub fn fold_with(&self, other: &FoldingProof) -> FoldingProof {
        FoldingProof {
            // 通过哈希将当前累加器哈希和另一个证明的哈希结合起来，生成新的累加器哈希
            acc_hash: h_join(["fold", &self.acc_hash, &other.acc_hash]),
        }
    }
}

/// 区块链的核心数据结构
#[derive(Debug, Default)]
pub struct Blockchain {
    // 存储所有区块的向量
    pub blocks: Vec<Block>,
    // 整个链的折叠证明累加器
    pub acc: FoldingProof,
}

impl Blockchain {
    /// 创建一个新的、空的区块链实例
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            acc: FoldingProof::default(), // 初始化折叠证明累加器
        }
    }

    /// 返回当前区块链的高度（即区块数量）
    pub fn height(&self) -> usize {
        self.blocks.len()
    }

    /// 返回链上最后一个区块的哈希值
    /// 如果链是空的，则返回创世块的哈希
    pub fn last_hash(&self) -> String {
        self.blocks
            .last()
            .map(|b| b.header_hash()) // 获取最后一个区块的头部哈希
            .unwrap_or_else(|| h_join(["genesis"])) // 如果没有区块，则返回 "genesis" 哈希
    }

    /// 向区块链中添加一个新区块
    pub fn add_block(&mut self, block: Block, folded_round_proof: Option<FoldingProof>) {
        // 如果提供了当轮的折叠证明，则将其合并到链的累加器中
        if let Some(fp) = folded_round_proof {
            self.acc = self.acc.fold_with(&fp);
        }
        // 将新区块添加到链上
        self.blocks.push(block);
    }
}
