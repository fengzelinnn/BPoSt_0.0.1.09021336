// 这个 mod.rs 文件将目录下的其他文件声明为 `roles` 模块的公共子模块。
// 这样，项目中的其他部分就可以通过 `use crate::roles::...` 来使用这些模块中定义的结构体和函数。

// 声明 file_owner.rs 为 `file_owner` 子模块
pub mod file_owner;
// 声明 miner.rs 为 `miner` 子模块
pub mod miner;
// 声明 prover.rs 为 `prover` 子模块
pub mod prover;
