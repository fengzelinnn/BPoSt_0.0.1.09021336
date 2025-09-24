use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 控制 P2P 模拟行为的一组参数。
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
    pub min_storage_rounds: usize,
    pub max_storage_rounds: usize,
}

#[derive(Debug, Error)]
pub enum DeploymentConfigError {
    #[error("无法读取部署配置文件 {path}: {source}")]
    Io {
        #[source]
        source: std::io::Error,
        path: String,
    },
    #[error("无法解析部署配置文件 {path}: {source}")]
    Parse {
        #[source]
        source: serde_json::Error,
        path: String,
    },
    #[error("部署配置无效: {message}")]
    Invalid { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeploymentConfig {
    #[serde(default)]
    pub nodes: Vec<NodeDeployment>,
    #[serde(default)]
    pub users: Vec<UserDeployment>,
    #[serde(default)]
    pub observer: Option<ObserverDeployment>,
    #[serde(default)]
    pub chunk_size: Option<usize>,
    #[serde(default)]
    pub min_file_kb: Option<usize>,
    #[serde(default)]
    pub max_file_kb: Option<usize>,
    #[serde(default)]
    pub bobtail_k: Option<usize>,
    #[serde(default)]
    pub default_storage_kb: Option<usize>,
    #[serde(default)]
    pub mining_difficulty_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDeployment {
    pub node_id: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub storage_kb: Option<usize>,
    #[serde(default)]
    pub chunk_size: Option<usize>,
    #[serde(default)]
    pub bobtail_k: Option<usize>,
    #[serde(default)]
    pub bootstrap: Option<String>,
    #[serde(default)]
    pub mining_difficulty_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDeployment {
    pub user_id: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub bootstrap: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverDeployment {
    pub observer_id: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub bootstrap: Option<String>,
}

impl DeploymentConfig {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, DeploymentConfigError> {
        let path_ref = path.as_ref();
        let data = fs::read_to_string(path_ref).map_err(|source| DeploymentConfigError::Io {
            source,
            path: path_ref.display().to_string(),
        })?;
        let cfg: DeploymentConfig =
            serde_json::from_str(&data).map_err(|source| DeploymentConfigError::Parse {
                source,
                path: path_ref.display().to_string(),
            })?;
        Ok(cfg)
    }

    pub fn ensure_nodes(&self) -> Result<(), DeploymentConfigError> {
        if self.nodes.is_empty() {
            return Err(DeploymentConfigError::Invalid {
                message: String::from("nodes 列表不能为空"),
            });
        }
        Ok(())
    }

    pub fn default_chunk_size(&self) -> usize {
        self.chunk_size
            .unwrap_or_else(|| P2PSimConfig::default().chunk_size)
    }

    pub fn default_bobtail_k(&self) -> usize {
        self.bobtail_k
            .unwrap_or_else(|| P2PSimConfig::default().bobtail_k)
    }

    pub fn default_storage_kb(&self) -> usize {
        self.default_storage_kb
            .or(self.nodes.iter().filter_map(|n| n.storage_kb).min())
            .unwrap_or_else(|| P2PSimConfig::default().min_storage_kb)
    }

    pub fn default_min_file_kb(&self) -> usize {
        self.min_file_kb
            .unwrap_or_else(|| P2PSimConfig::default().min_file_kb)
    }

    pub fn default_max_file_kb(&self) -> usize {
        self.max_file_kb
            .unwrap_or_else(|| P2PSimConfig::default().max_file_kb)
    }

    pub fn to_sim_config(&self) -> P2PSimConfig {
        let mut cfg = P2PSimConfig::default();
        cfg.num_nodes = self.nodes.len().max(1);
        cfg.num_file_owners = self.users.len();
        cfg.min_storage_nodes = cfg.num_nodes;
        cfg.max_storage_nodes = cfg.num_nodes;
        cfg.chunk_size = self.default_chunk_size();
        cfg.bobtail_k = self.default_bobtail_k();
        cfg.min_file_kb = self.default_min_file_kb();
        cfg.max_file_kb = self.default_max_file_kb();
        cfg.min_storage_kb = self.default_storage_kb();
        cfg.max_storage_kb = self.default_storage_kb().max(
            self.nodes
                .iter()
                .filter_map(|n| n.storage_kb)
                .max()
                .unwrap_or(cfg.min_storage_kb),
        );
        if let Some(first) = self.nodes.first() {
            cfg.base_port = first.port;
        }
        cfg
    }
}

impl Default for P2PSimConfig {
    /// 提供模拟的参考默认值。
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
            min_storage_rounds: 2,
            max_storage_rounds: 3,
        }
    }
}
