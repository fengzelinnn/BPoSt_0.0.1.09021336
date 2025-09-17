use std::env;
use std::net::SocketAddr;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::unbounded;
use rand::Rng;

use crate::config::P2PSimConfig;
use crate::p2p::node::Node;
use crate::p2p::user_node::UserNode;
use crate::roles::file_owner::FileOwner;
use crate::utils::log_msg;

pub fn run_p2p_simulation(config: P2PSimConfig) {
    log_msg(
        "INFO",
        "SIMULATOR",
        Some(String::from("MAIN")),
        &format!("正在使用配置启动模拟: {:?}", config),
    );
    let mut children: Vec<(String, Child)> = Vec::new();
    let host = "127.0.0.1".to_string();
    let bootstrap_addr = SocketAddr::new(host.parse().unwrap(), config.base_port);
    let mut current_port = config.base_port;
    let current_exe = std::env::current_exe().expect("无法定位当前可执行文件");
    let config_json = serde_json::to_string(&config).expect("无法序列化配置");

    for i in 0..config.num_nodes {
        let node_id = format!("S{}", i);
        let port = current_port;
        current_port += 1;
        let bootstrap = if i == 0 {
            String::from("none")
        } else {
            bootstrap_addr.to_string()
        };
        let storage_capacity =
            rand::thread_rng().gen_range(config.min_storage_kb..=config.max_storage_kb) * 1024;
        let mut cmd = Command::new(&current_exe);
        cmd.arg("node")
            .arg(node_id.clone())
            .arg(host.clone())
            .arg(port.to_string())
            .arg(bootstrap)
            .arg(config.chunk_size.to_string())
            .arg(storage_capacity.to_string())
            .arg(config.bobtail_k.to_string())
            .env("P2P_SIM_CONFIG", config_json.clone());
        match cmd.spawn() {
            Ok(child) => {
                log_msg(
                    "INFO",
                    "SIMULATOR",
                    Some(String::from("MAIN")),
                    &format!("已启动存储节点 {} 于端口 {}", node_id, port),
                );
                children.push((format!("node-{}", node_id), child));
            }
            Err(e) => {
                log_msg(
                    "ERROR",
                    "SIMULATOR",
                    Some(String::from("MAIN")),
                    &format!("启动存储节点 {} 失败: {}", node_id, e),
                );
            }
        }
    }

    for i in 0..config.num_file_owners {
        let port = current_port;
        current_port += 1;
        let owner_id = format!("U{}", i);
        let mut cmd = Command::new(&current_exe);
        cmd.arg("user")
            .arg(owner_id.clone())
            .arg(host.clone())
            .arg(port.to_string())
            .arg(bootstrap_addr.to_string())
            .env("P2P_SIM_CONFIG", config_json.clone());
        match cmd.spawn() {
            Ok(child) => {
                log_msg(
                    "INFO",
                    "SIMULATOR",
                    Some(String::from("MAIN")),
                    &format!("已启动用户节点 {} 于端口 {}", owner_id, port),
                );
                children.push((format!("user-{}", owner_id), child));
            }
            Err(e) => {
                log_msg(
                    "ERROR",
                    "SIMULATOR",
                    Some(String::from("MAIN")),
                    &format!("启动用户节点 {} 失败: {}", owner_id, e),
                );
            }
        }
    }

    log_msg(
        "INFO",
        "SIMULATOR",
        Some(String::from("MAIN")),
        &format!(
            "已启动 {} 个存储节点和 {} 个用户节点。",
            config.num_nodes, config.num_file_owners
        ),
    );
    log_msg(
        "INFO",
        "SIMULATOR",
        Some(String::from("MAIN")),
        &format!("共识和存储模拟将运行 {} 秒...", config.sim_duration_sec),
    );

    let sim_duration = Duration::from_secs(config.sim_duration_sec);
    let start = Instant::now();
    while start.elapsed() < sim_duration {
        thread::sleep(Duration::from_millis(500));
    }

    log_msg(
        "INFO",
        "SIMULATOR",
        Some(String::from("MAIN")),
        "模拟时间结束。正在停止节点并分析结果...",
    );
    for (name, mut child) in children {
        match child.try_wait() {
            Ok(Some(status)) => {
                log_msg(
                    "INFO",
                    "SIMULATOR",
                    Some(String::from("MAIN")),
                    &format!("进程 {} 已提前退出，状态: {}", name, status),
                );
            }
            Ok(None) => {
                if let Err(e) = child.kill() {
                    log_msg(
                        "ERROR",
                        "SIMULATOR",
                        Some(String::from("MAIN")),
                        &format!("终止进程 {} 失败: {}", name, e),
                    );
                }
                let _ = child.wait();
            }
            Err(e) => {
                log_msg(
                    "ERROR",
                    "SIMULATOR",
                    Some(String::from("MAIN")),
                    &format!("检查进程 {} 状态失败: {}", name, e),
                );
            }
        }
    }
    log_msg(
        "INFO",
        "SIMULATOR",
        Some(String::from("MAIN")),
        "模拟结束。",
    );
}

fn load_config_from_env() -> P2PSimConfig {
    let raw = env::var("P2P_SIM_CONFIG").expect("子进程缺少 P2P_SIM_CONFIG 环境变量");
    serde_json::from_str(&raw).expect("无法解析 P2P_SIM_CONFIG")
}

pub fn run_node_process_from_args<I>(mut args: I)
where
    I: Iterator<Item = String>,
{
    let node_id = args.next().expect("缺少节点ID参数");
    let host = args.next().expect("缺少主机参数");
    let port: u16 = args
        .next()
        .expect("缺少端口参数")
        .parse()
        .expect("无法解析端口");
    let bootstrap_arg = args.next().expect("缺少引导节点参数");
    let bootstrap_addr = if bootstrap_arg == "none" {
        None
    } else {
        Some(bootstrap_arg.parse().expect("无法解析引导节点地址"))
    };
    let chunk_size: usize = args
        .next()
        .expect("缺少数据块大小参数")
        .parse()
        .expect("无法解析数据块大小");
    let max_storage: usize = args
        .next()
        .expect("缺少存储容量参数")
        .parse()
        .expect("无法解析存储容量");
    let bobtail_k: usize = args
        .next()
        .expect("缺少 bobtail_k 参数")
        .parse()
        .expect("无法解析 bobtail_k");
    let (report_tx, _report_rx) = unbounded();
    let node = Node::new(
        node_id,
        host,
        port,
        bootstrap_addr,
        chunk_size,
        max_storage,
        bobtail_k,
        report_tx,
    );
    node.run();
}

pub fn run_user_process_from_args<I>(mut args: I)
where
    I: Iterator<Item = String>,
{
    let owner_id = args.next().expect("缺少用户ID参数");
    let host = args.next().expect("缺少主机参数");
    let port: u16 = args
        .next()
        .expect("缺少端口参数")
        .parse()
        .expect("无法解析端口");
    let bootstrap: SocketAddr = args
        .next()
        .expect("缺少引导节点参数")
        .parse()
        .expect("无法解析引导节点地址");
    let config = load_config_from_env();
    let owner = FileOwner::new(owner_id, config.chunk_size);
    let user = UserNode::new(owner, host, port, bootstrap, config.clone());
    user.run();
}
