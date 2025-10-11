use std::env;
use std::net::SocketAddr;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::unbounded;
use rand::Rng;

use crate::config::{
    DeploymentConfig, DeploymentConfigError, NodeDeployment, P2PSimConfig, PeerConfig,
};
use crate::p2p::node::{Node, DEFAULT_DIFFICULTY_HEX};
use crate::p2p::observer_node::ObserverNode;
use crate::p2p::user_node::UserNode;
use crate::roles::file_owner::FileOwner;
use crate::utils::log_msg;
use num_bigint::BigUint;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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
    let current_exe = env::current_exe().expect("无法定位当前可执行文件");
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
            .arg("start")
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
                let role_label = if i == 0 { "（引导节点）" } else { "" };
                log_msg(
                    "INFO",
                    "SIMULATOR",
                    Some(String::from("MAIN")),
                    &format!(
                        "已启动存储节点 {} 于端口 {}{}（分配存储容量: {} KB）",
                        node_id,
                        port,
                        role_label,
                        storage_capacity / 1024
                    ),
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
            "已启动 {} 个存储节点和 {} 个用户节点 (观察者角色已禁用)。",
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

pub fn run_deployment(config: DeploymentConfig) -> Result<(), DeploymentConfigError> {
    config.ensure_nodes()?;
    let sim_config = config.to_sim_config();
    let config_json = serde_json::to_string(&sim_config).expect("无法序列化部署配置");
    let current_exe = env::current_exe().expect("无法定位当前可执行文件");
    let default_bootstrap =
        normalize_node_addr(config.nodes.first().expect("至少应存在一个节点以供部署"))?;
    let default_storage_kb = config.default_storage_kb();
    let global_difficulty = if let Some(raw) = config.mining_difficulty_hex.as_ref() {
        Some(normalize_difficulty_hex(raw)?)
    } else {
        None
    };

    log_msg(
        "INFO",
        "DEPLOY",
        Some(String::from("CONFIG")),
        &format!(
            "一次性部署 {} 个存储节点、{} 个用户节点。文件大小范围: {}-{} KB, 块大小: {} 字节, Bobtail k 值: {}。",
            sim_config.num_nodes,
            sim_config.num_file_owners,
            sim_config.min_file_kb,
            sim_config.max_file_kb,
            sim_config.chunk_size,
            sim_config.bobtail_k
        ),
    );
    let difficulty_for_log = global_difficulty
        .clone()
        .unwrap_or_else(|| DEFAULT_DIFFICULTY_HEX.to_string());
    log_msg(
        "INFO",
        "DEPLOY",
        Some(String::from("CONFIG")),
        &format!("默认挖矿难度阈值: 0x{}", difficulty_for_log),
    );

    let mut children: Vec<(String, Child)> = Vec::new();
    for (idx, node_cfg) in config.nodes.iter().enumerate() {
        let chunk_size = node_cfg.chunk_size.unwrap_or(sim_config.chunk_size);
        let storage_kb = node_cfg.storage_kb.unwrap_or(default_storage_kb);
        let storage_bytes = storage_kb * 1024;
        let bobtail_k = node_cfg.bobtail_k.unwrap_or(sim_config.bobtail_k);
        let bootstrap = if let Some(override_bootstrap) = node_cfg.bootstrap.as_ref() {
            normalize_bootstrap_addr(override_bootstrap, true)?
        } else if idx == 0 {
            String::from("none")
        } else {
            default_bootstrap.clone()
        };
        let node_difficulty = if let Some(raw) = node_cfg.mining_difficulty_hex.as_ref() {
            Some(normalize_difficulty_hex(raw)?)
        } else {
            global_difficulty.clone()
        };
        log_msg(
            "INFO",
            "DEPLOY",
            Some(node_cfg.node_id.clone()),
            &format!(
                "节点将监听 {}:{}，存储容量 {} KB，数据块 {} 字节，Bobtail k = {}，挖矿难度 0x{}。",
                node_cfg.host,
                node_cfg.port,
                storage_kb,
                chunk_size,
                bobtail_k,
                node_difficulty
                    .clone()
                    .unwrap_or_else(|| DEFAULT_DIFFICULTY_HEX.to_string())
            ),
        );

        let mut cmd = Command::new(&current_exe);
        cmd.arg("node")
            .arg("start")
            .arg(node_cfg.node_id.clone())
            .arg(node_cfg.host.clone())
            .arg(node_cfg.port.to_string())
            .arg(bootstrap.clone())
            .arg(chunk_size.to_string())
            .arg(storage_bytes.to_string())
            .arg(bobtail_k.to_string())
            .env("P2P_SIM_CONFIG", config_json.clone());
        cmd.env_remove("BPST_STATIC_PEERS");
        if !node_cfg.peers.is_empty() {
            let peers_json =
                serde_json::to_string(&node_cfg.peers).expect("无法序列化静态对等节点配置");
            cmd.env("BPST_STATIC_PEERS", peers_json);
        }
        if let Some(diff_hex) = node_difficulty {
            cmd.env("BPST_MINING_DIFFICULTY_HEX", diff_hex);
        }

        match cmd.spawn() {
            Ok(child) => {
                log_msg(
                    "INFO",
                    "DEPLOY",
                    Some(node_cfg.node_id.clone()),
                    &format!("已启动节点进程，PID = {}", child.id()),
                );
                children.push((format!("node-{}", node_cfg.node_id), child));
            }
            Err(e) => {
                log_msg(
                    "ERROR",
                    "DEPLOY",
                    Some(node_cfg.node_id.clone()),
                    &format!("启动节点失败: {e}"),
                );
            }
        }
    }

    for user_cfg in &config.users {
        let bootstrap = if let Some(override_bootstrap) = user_cfg.bootstrap.as_ref() {
            normalize_bootstrap_addr(override_bootstrap, false)?
        } else {
            default_bootstrap.clone()
        };
        log_msg(
            "INFO",
            "DEPLOY",
            Some(user_cfg.user_id.clone()),
            &format!(
                "用户节点监听 {}:{}，连接引导节点 {}",
                user_cfg.host, user_cfg.port, bootstrap
            ),
        );
        let mut cmd = Command::new(&current_exe);
        cmd.arg("user")
            .arg(user_cfg.user_id.clone())
            .arg(user_cfg.host.clone())
            .arg(user_cfg.port.to_string())
            .arg(bootstrap)
            .env("P2P_SIM_CONFIG", config_json.clone());
        match cmd.spawn() {
            Ok(child) => {
                log_msg(
                    "INFO",
                    "DEPLOY",
                    Some(user_cfg.user_id.clone()),
                    &format!("已启动用户进程，PID = {}", child.id()),
                );
                children.push((format!("user-{}", user_cfg.user_id), child));
            }
            Err(e) => {
                log_msg(
                    "ERROR",
                    "DEPLOY",
                    Some(user_cfg.user_id.clone()),
                    &format!("启动用户节点失败: {e}"),
                );
            }
        }
    }

    if config.observer.is_some() {
        log_msg(
            "WARN",
            "DEPLOY",
            Some(String::from("CONFIG")),
            "检测到观察者配置，但观察者角色已禁用，此配置将被忽略。",
        );
    }

    let running = Arc::new(AtomicBool::new(true));
    let signal_flag = Arc::clone(&running);
    ctrlc::set_handler(move || {
        signal_flag.store(false, Ordering::SeqCst);
    })
    .map_err(|e| DeploymentConfigError::Invalid {
        message: format!("无法注册终止信号处理器: {e}"),
    })?;

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(5));
        let mut idx = 0;
        while idx < children.len() {
            let (name, child) = &mut children[idx];
            match child.try_wait() {
                Ok(Some(status)) => {
                    log_msg(
                        "WARN",
                        "DEPLOY",
                        Some(name.clone()),
                        &format!("进程已退出，状态: {status}"),
                    );
                    children.remove(idx);
                }
                Ok(None) => {
                    idx += 1;
                }
                Err(e) => {
                    log_msg(
                        "ERROR",
                        "DEPLOY",
                        Some(name.clone()),
                        &format!("检查子进程状态失败: {e}"),
                    );
                    idx += 1;
                }
            }
        }
        if children.is_empty() {
            log_msg(
                "WARN",
                "DEPLOY",
                Some(String::from("MAIN")),
                "所有子进程均已退出，部署进程将结束。",
            );
            return Ok(());
        }
    }

    log_msg(
        "INFO",
        "DEPLOY",
        Some(String::from("MAIN")),
        "收到终止信号，正在停止所有节点进程...",
    );
    for (name, mut child) in children {
        if let Err(e) = child.kill() {
            log_msg(
                "ERROR",
                "DEPLOY",
                Some(name.clone()),
                &format!("终止进程失败: {e}"),
            );
        }
        let _ = child.wait();
    }
    Ok(())
}

fn normalize_node_addr(node: &NodeDeployment) -> Result<String, DeploymentConfigError> {
    let addr = format!("{}:{}", node.host, node.port);
    addr.parse::<SocketAddr>()
        .map(|socket| socket.to_string())
        .map_err(|_| DeploymentConfigError::Invalid {
            message: format!("节点 {} 的监听地址无效: {}", node.node_id, addr),
        })
}

fn normalize_bootstrap_addr(addr: &str, allow_none: bool) -> Result<String, DeploymentConfigError> {
    if allow_none && addr.eq_ignore_ascii_case("none") {
        return Ok(String::from("none"));
    }
    addr.parse::<SocketAddr>()
        .map(|socket| socket.to_string())
        .map_err(|_| DeploymentConfigError::Invalid {
            message: format!("无效的引导节点地址: {addr}"),
        })
}

fn load_config_from_env() -> P2PSimConfig {
    let raw = env::var("P2P_SIM_CONFIG").expect("子进程缺少 P2P_SIM_CONFIG 环境变量");
    serde_json::from_str(&raw).expect("无法解析 P2P_SIM_CONFIG")
}

fn load_static_peers_from_env() -> Vec<(String, SocketAddr)> {
    let raw = match env::var("BPST_STATIC_PEERS") {
        Ok(val) if !val.trim().is_empty() => val,
        Ok(_) | Err(_) => return Vec::new(),
    };

    let peer_cfgs: Vec<PeerConfig> = match serde_json::from_str(&raw) {
        Ok(cfgs) => cfgs,
        Err(err) => {
            log_msg(
                "ERROR",
                "CONFIG",
                Some(String::from("STATIC_PEERS")),
                &format!("无法解析 BPST_STATIC_PEERS 环境变量: {err}"),
            );
            return Vec::new();
        }
    };

    let mut peers = Vec::new();
    for peer in peer_cfgs {
        let addr_str = format!("{}:{}", peer.host, peer.port);
        match addr_str.parse::<SocketAddr>() {
            Ok(addr) => peers.push((peer.node_id, addr)),
            Err(err) => {
                log_msg(
                    "WARN",
                    "CONFIG",
                    Some(String::from("STATIC_PEERS")),
                    &format!("忽略无效的静态对等节点地址 {}: {}", addr_str, err),
                );
            }
        }
    }

    peers
}

fn load_difficulty_override_from_env() -> Option<BigUint> {
    match env::var("BPST_MINING_DIFFICULTY_HEX") {
        Ok(raw) => parse_difficulty_hex(&raw),
        Err(_) => None,
    }
}

fn parse_difficulty_hex(raw: &str) -> Option<BigUint> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    BigUint::parse_bytes(normalized.as_bytes(), 16)
}

fn normalize_difficulty_hex(raw: &str) -> Result<String, DeploymentConfigError> {
    parse_difficulty_hex(raw)
        .map(|v| format!("{:x}", v))
        .ok_or_else(|| DeploymentConfigError::Invalid {
            message: format!("无效的挖矿难度十六进制值: {raw}"),
        })
}

pub fn run_node_process_from_args<I>(args: I)
where
    I: Iterator<Item = String>,
{
    let params: Vec<String> = args.collect();
    let mut iter = params.into_iter();
    let mut node_id = iter.next().expect("缺少节点ID或子命令");
    if node_id.eq_ignore_ascii_case("start") {
        node_id = iter.next().expect("缺少节点ID参数");
    }
    let host = iter.next().expect("缺少主机参数");
    let port: u16 = iter
        .next()
        .expect("缺少端口参数")
        .parse()
        .expect("无法解析端口");
    let bootstrap_arg = iter.next().expect("缺少引导节点参数");
    let bootstrap_addr = if bootstrap_arg == "none" {
        None
    } else {
        Some(bootstrap_arg.parse().expect("无法解析引导节点地址"))
    };
    let chunk_size: usize = iter
        .next()
        .expect("缺少数据块大小参数")
        .parse()
        .expect("无法解析数据块大小");
    let max_storage: usize = iter
        .next()
        .expect("缺少存储容量参数")
        .parse()
        .expect("无法解析存储容量");
    let bobtail_k: usize = iter
        .next()
        .expect("缺少 bobtail_k 参数")
        .parse()
        .expect("无法解析 bobtail_k");
    let difficulty_override = load_difficulty_override_from_env();
    let (report_tx, _report_rx) = unbounded();
    let static_peers = load_static_peers_from_env();
    let node = Box::new(Node::new(
        node_id,
        host,
        port,
        bootstrap_addr,
        static_peers,
        chunk_size,
        max_storage,
        bobtail_k,
        difficulty_override,
        report_tx,
    ));
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
    // --- 新增逻辑 ---
    // 从环境变量 BPST_ADVERTISE_IP 读取外部IP，如果不存在则回退为监听IP
    let advertise_host = env::var("BPST_ADVERTISE_IP").unwrap_or_else(|_| host.clone());
    // ----------------

    let owner = FileOwner::new(owner_id, config.chunk_size);
    // --- 将新的 advertise_host 传给构造函数 ---
    let user = Box::new(UserNode::new(
        owner,
        host,
        advertise_host,
        port,
        bootstrap,
        config.clone(),
    ));
    // ----------------------------------------
    user.run();
}

pub fn run_observer_process_from_args<I>(mut args: I)
where
    I: Iterator<Item = String>,
{
    let observer_id = args.next().expect("缺少观察者ID参数");
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
    let _config = load_config_from_env();
    let observer = ObserverNode::new(observer_id, host, port, bootstrap, Duration::from_secs(60));
    observer.run();
}
