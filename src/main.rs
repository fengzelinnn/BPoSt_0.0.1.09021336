// 引入 bpst 项目中的配置模块
use bpst::config::{DeploymentConfig, P2PSimConfig};
// 初始化日志系统
use bpst::utils::init_logging;
// 引入 bpst 项目中的 simulation 模块，包含运行节点、用户进程和P2P模拟的功能
use bpst::simulation::{
    run_deployment, run_node_process_from_args, run_observer_process_from_args, run_p2p_simulation,
    run_user_process_from_args,
};
use log::error;

// Rust 程序的主入口函数
fn main() {
    // 初始化日志系统，确保控制台输出同时写入日志文件
    init_logging();
    // 获取命令行参数的迭代器
    let mut args = std::env::args();
    // 跳过可执行文件路径
    let _exe = args.next();
    // 获取下一个参数作为子命令
    if let Some(subcommand) = args.next() {
        // 匹配子命令
        match subcommand.as_str() {
            // 如果子命令是 "node"
            "node" => {
                // 从参数运行节点进程
                run_node_process_from_args(args);
                // 结束程序
                return;
            }
            // 如果子命令是 "user"
            "user" => {
                // 从参数运行用户进程
                run_user_process_from_args(args);
                // 结束程序
                return;
            }
            "observer" => {
                run_observer_process_from_args(args);
                return;
            }
            "deploy" => {
                let config_path = args
                    .next()
                    .expect("缺少部署配置文件路径参数，例如: bpst deploy ./deployment/config.json");
                let deployment_config = match DeploymentConfig::from_path(&config_path) {
                    Ok(config) => config,
                    Err(err) => {
                        error!("无法加载部署配置文件 {}: {}", config_path, err);
                        std::process::exit(1);
                    }
                };
                if let Err(err) = run_deployment(deployment_config) {
                    error!("部署失败: {}", err);
                    std::process::exit(1);
                }
                return;
            }
            // 忽略其他子命令
            _ => {}
        }
    }
    // 如果没有子命令，则运行P2P模拟
    // 定义 P2P 模拟的配置
    let config = P2PSimConfig {
        num_nodes: 7,            // 节点数量
        num_file_owners: 2,      // 文件所有者数量
        sim_duration_sec: 90000, // 模拟持续时间（秒）
        chunk_size: 64,          // 数据块大小
        min_file_kb: 1,          // 最小文件大小 (KB)
        max_file_kb: 1,          // 最大文件大小 (KB)
        min_storage_nodes: 2,    // 最小存储节点数
        max_storage_nodes: 5,    // 最大存储节点数
        base_port: 62000,        // 基础端口号
        bobtail_k: 3,            // Bobtail 参数 K
        min_storage_kb: 128,     // 最小存储空间 (KB)
        max_storage_kb: 256,     // 最大存储空间 (KB)
        bid_wait_sec: 20,        // 投标等待时间（秒）
        min_storage_rounds: 5,   // 最小存储轮次
        max_storage_rounds: 7,   // 最大存储轮次
    };
    // 运行 P2P 网络模拟
    run_p2p_simulation(config);
}
