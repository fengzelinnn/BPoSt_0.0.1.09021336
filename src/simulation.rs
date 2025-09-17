use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::unbounded;
use rand::Rng;

use crate::config::P2PSimConfig;
use crate::p2p::node::{Node, NodeReport};
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
    let (report_tx, report_rx) = unbounded::<NodeReport>();
    let mut handles = Vec::new();
    let mut stop_flags = Vec::new();
    let host = "127.0.0.1".to_string();
    let bootstrap_addr = SocketAddr::new(host.parse().unwrap(), config.base_port);
    let mut current_port = config.base_port;

    for i in 0..config.num_nodes {
        let node_id = format!("S{}", i);
        let port = current_port;
        current_port += 1;
        let bootstrap = if i == 0 { None } else { Some(bootstrap_addr) };
        let node = Node::new(
            node_id.clone(),
            host.clone(),
            port,
            bootstrap,
            config.chunk_size,
            rand::thread_rng().gen_range(config.min_storage_kb..=config.max_storage_kb) * 1024,
            config.bobtail_k,
            report_tx.clone(),
        );
        let stop_handle = node.stop_handle();
        let handle = thread::spawn(move || node.run());
        handles.push(handle);
        stop_flags.push(stop_handle);
    }

    for i in 0..config.num_file_owners {
        let owner = FileOwner::new(format!("U{}", i), config.chunk_size);
        let port = current_port;
        current_port += 1;
        let user = UserNode::new(owner, host.clone(), port, bootstrap_addr, config.clone());
        let stop_handle = user.stop_handle();
        let handle = thread::spawn(move || user.run());
        handles.push(handle);
        stop_flags.push(stop_handle);
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
        if let Ok(report) = report_rx.recv_timeout(Duration::from_millis(500)) {
            log_msg(
                "INFO",
                "NODE_STATUS",
                Some(report.node_id),
                &format!(
                    "高度={} 头部={} peers={} mempool={} proofs={} mining={}",
                    report.chain_height,
                    report.chain_head,
                    report.peers,
                    report.mempool_size,
                    report.proof_pool_size,
                    report.is_mining
                ),
            );
        }
    }

    log_msg(
        "INFO",
        "SIMULATOR",
        Some(String::from("MAIN")),
        "模拟时间结束。正在停止节点并分析结果...",
    );
    for flag in stop_flags {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    for handle in handles {
        let _ = handle.join();
    }
    log_msg(
        "INFO",
        "SIMULATOR",
        Some(String::from("MAIN")),
        "模拟结束。",
    );
}
