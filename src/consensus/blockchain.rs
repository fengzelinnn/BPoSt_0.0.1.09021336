use crate::common::datastructures::Block;
use crate::utils::h_join;

#[derive(Debug, Clone)]
pub struct FoldingProof {
    pub acc_hash: String,
}

impl Default for FoldingProof {
    fn default() -> Self {
        Self {
            acc_hash: h_join(["init_acc"]),
        }
    }
}

impl FoldingProof {
    pub fn fold_with(&self, other: &FoldingProof) -> FoldingProof {
        FoldingProof {
            acc_hash: h_join(["fold", &self.acc_hash, &other.acc_hash]),
        }
    }
}

#[derive(Debug, Default)]
pub struct Blockchain {
    pub blocks: Vec<Block>,
    pub acc: FoldingProof,
}

impl Blockchain {
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            acc: FoldingProof::default(),
        }
    }

    pub fn height(&self) -> usize {
        self.blocks.len()
    }

    pub fn last_hash(&self) -> String {
        self.blocks
            .last()
            .map(|b| b.header_hash())
            .unwrap_or_else(|| h_join(["genesis"]))
    }

    pub fn add_block(&mut self, block: Block, folded_round_proof: Option<FoldingProof>) {
        if let Some(fp) = folded_round_proof {
            self.acc = self.acc.fold_with(&fp);
        }
        self.blocks.push(block);
    }
}
