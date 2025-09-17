use rand::{Rng, RngCore};

use crate::common::datastructures::{DPDPParams, DPDPTags, FileChunk};
use crate::crypto::dpdp::DPDP;
use crate::utils::log_msg;

pub struct FileOwner {
    pub owner_id: String,
    pub chunk_size: usize,
    pub params: DPDPParams,
    pub tags: DPDPTags,
    pub file_id: String,
}

impl FileOwner {
    pub fn new(owner_id: String, chunk_size: usize) -> Self {
        let params = DPDP::key_gen();
        let tags = DPDPTags { tags: Vec::new() };
        let file_id = format!("file_{}_{}", owner_id, rand::random::<u64>());
        Self {
            owner_id,
            chunk_size,
            params,
            tags,
            file_id,
        }
    }

    pub fn get_dpdp_params(&self) -> &DPDPParams {
        &self.params
    }

    fn create_file(&self, size_bytes: usize) -> Vec<u8> {
        let mut data = vec![0u8; size_bytes];
        rand::thread_rng().fill_bytes(&mut data);
        data
    }

    fn split_file(&self, data: &[u8]) -> Vec<Vec<u8>> {
        data.chunks(self.chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    pub fn dpdp_setup(&mut self, file_bytes: &[u8]) -> Vec<FileChunk> {
        let raw_chunks = self.split_file(file_bytes);
        let tags = DPDP::tag_file(&self.params, &raw_chunks);
        let chunks: Vec<FileChunk> = raw_chunks
            .into_iter()
            .enumerate()
            .map(|(i, data)| FileChunk {
                index: i,
                data,
                tag: tags.tags[i].clone(),
                file_id: self.file_id.clone(),
            })
            .collect();
        self.tags = tags;
        chunks
    }

    pub fn get_file_num_chunks(&self) -> usize {
        self.tags.tags.len()
    }

    pub fn prepare_storage_request(
        &mut self,
        min_size_bytes: usize,
        max_size_bytes: usize,
        num_nodes: usize,
    ) -> (Vec<FileChunk>, usize) {
        let file_size = rand::thread_rng().gen_range(min_size_bytes..=max_size_bytes);
        let file_bytes = self.create_file(file_size);
        log_msg(
            "INFO",
            "OWNER",
            Some(self.owner_id.clone()),
            &format!("创建了大小为 {} 字节的随机文件 {}", file_size, self.file_id),
        );
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
        (chunks, num_nodes)
    }
}
