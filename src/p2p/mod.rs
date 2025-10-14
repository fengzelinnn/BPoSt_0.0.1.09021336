use serde::{Deserialize, Serialize};

pub mod node;
pub mod observer_node;
pub mod user_node;

/// 表示参与 P2P 网络的不同节点角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeType {
    User,
    Storage,
    Bootstrap,
}

impl NodeType {
    /// 将字符串转换为枚举值，忽略大小写。
    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "user" => Some(Self::User),
            "storage" => Some(Self::Storage),
            "bootstrap" => Some(Self::Bootstrap),
            _ => None,
        }
    }

    /// 返回角色的标准字符串表示。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Storage => "storage",
            Self::Bootstrap => "bootstrap",
        }
    }
}
