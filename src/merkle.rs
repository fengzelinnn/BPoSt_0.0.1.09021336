use serde::{Deserialize, Serialize};

use crate::utils::h_join;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub leaves: Vec<String>,
    pub levels: Vec<Vec<String>>,
}

impl MerkleTree {
    pub fn new(leaves: &[String]) -> Self {
        let mut tree = Self {
            leaves: leaves.to_vec(),
            levels: Vec::new(),
        };
        if !tree.leaves.is_empty() {
            tree.build();
        } else {
            tree.levels.push(Vec::new());
        }
        tree
    }

    fn build(&mut self) {
        let mut level = self.leaves.clone();
        self.levels.push(level.clone());
        while level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in level.chunks(2) {
                let left = &chunk[0];
                let right = if chunk.len() > 1 { &chunk[1] } else { left };
                let parent = h_join(["merkle", left, right]);
                next_level.push(parent);
            }
            level = next_level.clone();
            self.levels.push(level.clone());
        }
    }

    pub fn root(&self) -> String {
        if self.leaves.is_empty() {
            return h_join(["empty"]);
        }
        self.levels
            .last()
            .and_then(|lvl| lvl.first())
            .cloned()
            .unwrap_or_else(|| h_join(["empty"]))
    }

    pub fn prove(&self, index: usize) -> Vec<(String, char)> {
        if self.leaves.is_empty() || index >= self.leaves.len() {
            return Vec::new();
        }
        let mut proof = Vec::new();
        let mut current_idx = index;
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            let sib_idx = current_idx ^ 1;
            let sibling = level
                .get(sib_idx)
                .cloned()
                .unwrap_or_else(|| level[current_idx].clone());
            let direction = if current_idx % 2 == 0 { 'R' } else { 'L' };
            proof.push((sibling, direction));
            current_idx /= 2;
        }
        proof
    }

    pub fn verify(leaf: &str, _index: usize, proof: &[(String, char)], root: &str) -> bool {
        let mut computed = leaf.to_string();
        for (sibling, direction) in proof {
            if *direction == 'R' {
                computed = h_join(["merkle", &computed, sibling]);
            } else {
                computed = h_join(["merkle", sibling, &computed]);
            }
        }
        computed == root
    }
}
