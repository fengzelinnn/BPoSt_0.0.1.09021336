use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::merkle::MerkleTree;
use crate::utils::h_join;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeStateTree {
    pub leaves: HashMap<usize, String>,
    #[serde(skip)]
    pub merkle: Option<MerkleTree>,
}

impl Default for TimeStateTree {
    fn default() -> Self {
        Self {
            leaves: HashMap::new(),
            merkle: None,
        }
    }
}

impl TimeStateTree {
    pub fn build(&mut self) {
        if self.leaves.is_empty() {
            self.merkle = Some(MerkleTree::new(&[]));
            return;
        }
        let max_index = self.leaves.keys().copied().max().unwrap();
        let seq: Vec<String> = (0..=max_index)
            .map(|i| {
                self.leaves
                    .get(&i)
                    .cloned()
                    .unwrap_or_else(|| h_join(["missing", &i.to_string()]))
            })
            .collect();
        self.merkle = Some(MerkleTree::new(&seq));
    }

    pub fn root(&self) -> String {
        self.merkle
            .as_ref()
            .map(|m| m.root())
            .unwrap_or_else(|| h_join(["empty"]))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStateTree {
    pub file_roots: HashMap<String, String>,
    #[serde(skip)]
    pub merkle: Option<MerkleTree>,
}

impl Default for StorageStateTree {
    fn default() -> Self {
        Self {
            file_roots: HashMap::new(),
            merkle: None,
        }
    }
}

impl StorageStateTree {
    pub fn build(&mut self) {
        let mut entries: Vec<(String, String)> = self
            .file_roots
            .iter()
            .map(|(fid, root)| (fid.clone(), root.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let seq: Vec<String> = entries.into_iter().map(|(_, root)| root).collect();
        self.merkle = Some(MerkleTree::new(&seq));
    }

    pub fn root(&self) -> String {
        self.merkle
            .as_ref()
            .map(|m| m.root())
            .unwrap_or_else(|| h_join(["empty"]))
    }
}

#[derive(Debug, Default)]
pub struct ServerStorage {
    pub time_trees: HashMap<String, TimeStateTree>,
    pub storage_tree: Option<StorageStateTree>,
}

impl ServerStorage {
    pub fn add_chunk_commitment(&mut self, file_id: &str, index: usize, commitment: String) {
        self.time_trees
            .entry(file_id.to_string())
            .or_default()
            .leaves
            .insert(index, commitment);
    }

    pub fn build_state(&mut self) {
        for tst in self.time_trees.values_mut() {
            tst.build();
        }
        let mut file_roots = HashMap::new();
        for (fid, tst) in &self.time_trees {
            file_roots.insert(fid.clone(), tst.root());
        }
        let mut storage_tree = StorageStateTree {
            file_roots,
            merkle: None,
        };
        storage_tree.build();
        self.storage_tree = Some(storage_tree);
    }

    pub fn storage_root(&self) -> String {
        self.storage_tree
            .as_ref()
            .map(|st| st.root())
            .unwrap_or_else(|| h_join(["empty"]))
    }

    pub fn num_files(&self) -> usize {
        self.time_trees.len()
    }
}
