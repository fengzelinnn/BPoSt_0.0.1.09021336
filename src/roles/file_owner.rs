// 导入随机数生成器相关的 trait
use rand::{Rng, RngCore};

// 导入项目内的数据结构和密码学模块
use crate::common::datastructures::{DPDPParams, DPDPTags, FileChunk};
use crate::crypto::dpdp::DPDP;
use crate::utils::log_msg;

/// FileOwner 结构体定义了文件所有者的角色
/// 文件所有者是数据的源头。它负责：
/// 1. 生成 dPDP 方案所需的密钥对（公钥和私钥）。
/// 2. 创建文件数据。
/// 3. 对文件数据进行预处理，生成 dPDP 标签（tags）。
/// 4. 将文件分割成块，并将每个块与其对应的标签打包，准备分发给存储节点。
pub struct FileOwner {
    // 文件所有者的唯一 ID
    pub owner_id: String,
    // 文件分块的大小（字节）
    pub chunk_size: usize,
    // dPDP 参数，包含公钥和私钥
    pub params: DPDPParams,
    // 为特定文件生成的 dPDP 标签集合
    pub tags: DPDPTags,
    // 文件的唯一 ID
    pub file_id: String,
}

impl FileOwner {
    fn generate_file_id(owner_id: &str) -> String {
        format!("file_{}_{}", owner_id, rand::random::<u64>())
    }

    /// 创建一个新的 FileOwner 实例
    pub fn new(owner_id: String, chunk_size: usize) -> Self {
        // 1. 生成 dPDP 密钥对
        let params = DPDP::key_gen();
        // 2. 初始化一个空的标签集合
        let tags = DPDPTags { tags: Vec::new() };
        // 3. 创建一个唯一的 file_id
        let file_id = Self::generate_file_id(&owner_id);
        Self {
            owner_id,
            chunk_size,
            params,
            tags,
            file_id,
        }
    }

    /// 获取 dPDP 参数的引用
    pub fn get_dpdp_params(&self) -> &DPDPParams {
        &self.params
    }

    /// 创建一个指定大小的随机文件内容
    fn create_file(&self, size_bytes: usize) -> Vec<u8> {
        let mut data = vec![0u8; size_bytes];
        rand::thread_rng().fill_bytes(&mut data); // 使用随机字节填充
        data
    }

    /// 将文件数据按设定的 chunk_size 分割成多个块
    fn split_file(&self, data: &[u8]) -> Vec<Vec<u8>> {
        data.chunks(self.chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    /// dPDP 设置阶段：为文件生成标签并打包成块
    /// 这是将原始文件转化为可被 dPDP 方案保护的格式的关键步骤
    pub fn dpdp_setup(&mut self, file_bytes: &[u8]) -> Vec<FileChunk> {
        // 1. 将文件字节流分割成原始数据块
        let raw_chunks = self.split_file(file_bytes);
        // 2. 使用 dPDP 私钥为所有数据块生成对应的标签
        let tags = DPDP::tag_file(&self.params, &raw_chunks);
        // 3. 将原始数据块和生成的标签打包成 FileChunk 结构体
        let chunks: Vec<FileChunk> = raw_chunks
            .into_iter()
            .enumerate()
            .map(|(i, data)| FileChunk {
                index: i,                      // 块的索引
                data,                          // 块的原始数据
                tag: tags.tags[i].clone(),     // 对应的 dPDP 标签
                file_id: self.file_id.clone(), // 文件 ID
            })
            .collect();
        // 4. 保存生成的标签集到 FileOwner 实例中
        self.tags = tags;
        chunks
    }

    /// 获取文件被分割成的总块数
    pub fn get_file_num_chunks(&self) -> usize {
        self.tags.tags.len()
    }

    /// 准备一个存储请求
    /// 这个函数模拟了文件所有者准备将一个新文件存入系统的完整流程
    pub fn prepare_storage_request(
        &mut self,
        min_size_bytes: usize, // 随机生成文件的最小尺寸
        max_size_bytes: usize, // 随机生成文件的最大尺寸
        num_nodes: usize,      // 期望存储该文件的节点数量（当前实现中未直接使用，但可用于分发策略）
    ) -> (Vec<FileChunk>, usize) {
        // 在发起新的存储请求前生成一个全新的文件 ID，避免重复使用导致冲突
        self.file_id = Self::generate_file_id(&self.owner_id);
        // 1. 在指定范围内随机确定文件大小
        let file_size = rand::thread_rng().gen_range(min_size_bytes..=max_size_bytes);
        // 2. 创建具有该大小的随机文件内容
        let file_bytes = self.create_file(file_size);
        log_msg(
            "INFO",
            "OWNER",
            Some(self.owner_id.clone()),
            &format!("创建了大小为 {} 字节的随机文件 {}", file_size, self.file_id),
        );
        // 3. 执行 dPDP 设置，生成带标签的文件块
        let chunks = self.dpdp_setup(&file_bytes);
        log_msg(
            "INFO",
            "OWNER",
            Some(self.owner_id.clone()),
            &format!(
                "为文件 {} 生成了 {} 个数据块和dPDP标签",
                self.file_id,
                chunks.len()
            ),
        );
        // 4. 返回所有文件块和期望的节点数
        (chunks, num_nodes)
    }
}
