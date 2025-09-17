use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PSimConfig {
    pub num_nodes: usize,
    pub num_file_owners: usize,
    pub sim_duration_sec: u64,
    pub chunk_size: usize,
    pub min_file_kb: usize,
    pub max_file_kb: usize,
    pub min_storage_nodes: usize,
    pub max_storage_nodes: usize,
    pub base_port: u16,
    pub bobtail_k: usize,
    pub min_storage_kb: usize,
    pub max_storage_kb: usize,
    pub bid_wait_sec: u64,
}

impl Default for P2PSimConfig {
    fn default() -> Self {
        Self {
            num_nodes: 15,
            num_file_owners: 5,
            sim_duration_sec: 90,
            chunk_size: 1024,
            min_file_kb: 16,
            max_file_kb: 24,
            min_storage_nodes: 4,
            max_storage_nodes: 8,
            base_port: 62000,
            bobtail_k: 3,
            min_storage_kb: 512,
            max_storage_kb: 2048,
            bid_wait_sec: 20,
        }
    }
}
