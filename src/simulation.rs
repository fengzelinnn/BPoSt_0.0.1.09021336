use std::collections::hash_map::DefaultHasher;
use std::convert::TryFrom;
use std::env;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Duration as ChronoDuration;
use chrono::{DateTime, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use crossbeam_channel::unbounded;
use rand::Rng;

use crate::config::{
    DeploymentConfig, DeploymentConfigError, DeploymentSchedule, NodeDeployment, P2PSimConfig,
    PeerConfig,
};
use crate::p2p::node::{Node, DEFAULT_DIFFICULTY_HEX};
use crate::p2p::observer_node::ObserverNode;
use crate::p2p::user_node::UserNode;
use crate::roles::file_owner::FileOwner;
use crate::utils::log_msg;
use num_bigint::BigUint;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const DEFAULT_MAX_CLOCK_SKEW_SEC: u64 = 300;

struct ResolvedSchedule {
    start_at: DateTime<Utc>,
    max_drift_sec: u64,
    jitter_sec: Option<u64>,
}

fn resolve_deployment_schedule(
    schedule_cfg: Option<&DeploymentSchedule>,
) -> Result<Option<ResolvedSchedule>, DeploymentConfigError> {
    let Some(schedule_cfg) = schedule_cfg else {
        return Ok(None);
    };

    let start_at = if let Some(raw) = schedule_cfg.start_at_utc.as_ref().and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    }) {
        parse_schedule_datetime(&raw)?
    } else if let Some(delay) = schedule_cfg.start_after_sec {
        let delay = i64::try_from(delay).map_err(|_| DeploymentConfigError::Invalid {
            message: String::from("schedule.start_after_sec 超出支持的范围"),
        })?;
        Utc::now() + ChronoDuration::seconds(delay)
    } else {
        return Ok(None);
    };

    let max_drift_sec = schedule_cfg
        .max_clock_skew_sec
        .unwrap_or(DEFAULT_MAX_CLOCK_SKEW_SEC);
    if max_drift_sec == 0 {
        return Err(DeploymentConfigError::Invalid {
            message: String::from("schedule.max_clock_skew_sec 必须大于 0"),
        });
    }

    let now = Utc::now();
    if start_at < now {
        let elapsed = now.signed_duration_since(start_at).num_seconds();
        if elapsed > max_drift_sec as i64 {
            return Err(DeploymentConfigError::Invalid {
                message: format!(
                    "统一启动时间 {} 已经过期 {} 秒，超过允许的时钟偏移 ±{} 秒",
                    start_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                    elapsed,
                    max_drift_sec
                ),
            });
        }
    }

    let jitter_sec = schedule_cfg.jitter_sec.filter(|value| *value > 0);

    Ok(Some(ResolvedSchedule {
        start_at,
        max_drift_sec,
        jitter_sec,
    }))
}

fn parse_schedule_datetime(raw: &str) -> Result<DateTime<Utc>, DeploymentConfigError> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Ok(dt.with_timezone(&Utc));
    }

    if let Ok(ts) = raw.parse::<i64>() {
        if let Some(dt) = Utc.timestamp_opt(ts, 0).single() {
            return Ok(dt);
        }
    }

    if let Ok(naive) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S") {
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }

    Err(DeploymentConfigError::Invalid {
        message: format!("无法解析统一启动时间: {raw}"),
    })
}

fn apply_schedule_env(cmd: &mut Command, schedule: &ResolvedSchedule) {
    let iso = schedule.start_at.to_rfc3339_opts(SecondsFormat::Secs, true);
    cmd.env("BPST_CLUSTER_START_UTC", iso);
    cmd.env(
        "BPST_CLUSTER_START_UNIX",
        schedule.start_at.timestamp().to_string(),
    );
    cmd.env(
        "BPST_CLUSTER_START_MAX_DRIFT_SEC",
        schedule.max_drift_sec.to_string(),
    );
    if let Some(jitter) = schedule.jitter_sec {
        cmd.env("BPST_CLUSTER_START_JITTER_SEC", jitter.to_string());
    } else {
        cmd.env_remove("BPST_CLUSTER_START_JITTER_SEC");
    }
}

fn startup_schedule_from_env() -> Result<Option<ResolvedSchedule>, String> {
    let start_at = if let Some(raw) = env_var_non_empty("BPST_CLUSTER_START_UNIX") {
        let ts = raw
            .parse::<i64>()
            .map_err(|e| format!("无法解析 BPST_CLUSTER_START_UNIX: {e}"))?;
        Utc.timestamp_opt(ts, 0)
            .single()
            .ok_or_else(|| String::from("BPST_CLUSTER_START_UNIX 超出有效范围"))?
    } else if let Some(raw) = env_var_non_empty("BPST_CLUSTER_START_UTC") {
        parse_schedule_datetime(&raw)
            .map_err(|e| format!("解析 BPST_CLUSTER_START_UTC 失败: {e}"))?
    } else if let Some(raw) = env_var_non_empty("BPST_CLUSTER_START_DELAY_SEC") {
        let delay = raw
            .parse::<i64>()
            .map_err(|e| format!("无法解析 BPST_CLUSTER_START_DELAY_SEC: {e}"))?;
        if delay < 0 {
            return Err(String::from("BPST_CLUSTER_START_DELAY_SEC 不能为负数"));
        }
        Utc::now() + ChronoDuration::seconds(delay)
    } else {
        return Ok(None);
    };

    let max_drift_sec = env_var_non_empty("BPST_CLUSTER_START_MAX_DRIFT_SEC")
        .map(|raw| {
            raw.parse::<u64>()
                .map_err(|e| format!("无法解析 BPST_CLUSTER_START_MAX_DRIFT_SEC: {e}"))
        })
        .transpose()?
        .unwrap_or(DEFAULT_MAX_CLOCK_SKEW_SEC);
    if max_drift_sec == 0 {
        return Err(String::from("BPST_CLUSTER_START_MAX_DRIFT_SEC 必须大于 0"));
    }

    let jitter_sec = env_var_non_empty("BPST_CLUSTER_START_JITTER_SEC")
        .map(|raw| {
            raw.parse::<u64>()
                .map_err(|e| format!("无法解析 BPST_CLUSTER_START_JITTER_SEC: {e}"))
        })
        .transpose()?
        .filter(|value| *value > 0);

    Ok(Some(ResolvedSchedule {
        start_at,
        max_drift_sec,
        jitter_sec,
    }))
}

fn env_var_non_empty(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        Err(_) => None,
    }
}

fn wait_for_start_signal(role: &str, id: &str) {
    match startup_schedule_from_env() {
        Ok(Some(schedule)) => wait_on_schedule(&schedule, role, id),
        Ok(None) => {}
        Err(err) => {
            log_msg(
                "ERROR",
                "STARTUP",
                Some(format!("{}:{}", role, id)),
                &format!("统一启动调度配置无效: {err}"),
            );
        }
    }
}

fn wait_on_schedule(schedule: &ResolvedSchedule, role: &str, id: &str) {
    let context = Some(format!("{}:{}", role, id));
    let iso = schedule.start_at.to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut announced = false;
    let mut last_reminder = Instant::now();

    loop {
        let now = Utc::now();
        match schedule.start_at.signed_duration_since(now).to_std() {
            Ok(remaining) if remaining > Duration::from_secs(0) => {
                if !announced {
                    log_msg(
                        "INFO",
                        "STARTUP",
                        context.clone(),
                        &format!(
                            "统一启动时间 {} 尚未到达，剩余约 {} 秒，等待所有实例对齐...",
                            iso,
                            remaining.as_secs()
                        ),
                    );
                    announced = true;
                    last_reminder = Instant::now();
                } else if last_reminder.elapsed() >= Duration::from_secs(30)
                    && remaining.as_secs() > 30
                {
                    log_msg(
                        "INFO",
                        "STARTUP",
                        context.clone(),
                        &format!(
                            "距离统一启动时间 {} 仍有约 {} 秒...",
                            iso,
                            remaining.as_secs()
                        ),
                    );
                    last_reminder = Instant::now();
                }

                let sleep_for = if remaining > Duration::from_secs(5) {
                    Duration::from_secs(5)
                } else {
                    remaining
                };
                thread::sleep(sleep_for);
            }
            _ => break,
        }
    }

    let now = Utc::now();
    let lateness = now.signed_duration_since(schedule.start_at).num_seconds();
    if lateness > 0 {
        let message = if lateness > schedule.max_drift_sec as i64 {
            format!(
                "已经晚于统一启动时间 {} 共 {} 秒，超过允许的偏移 ±{} 秒，仍尝试继续启动。",
                iso, lateness, schedule.max_drift_sec
            )
        } else {
            format!(
                "比统一启动时间 {} 晚 {} 秒，但仍在允许的偏移 ±{} 秒内。",
                iso, lateness, schedule.max_drift_sec
            )
        };
        log_msg("WARN", "STARTUP", context.clone(), &message);
    } else {
        log_msg(
            "INFO",
            "STARTUP",
            context.clone(),
            &format!("达到统一启动时间 {}，开始初始化。", iso),
        );
    }

    if let Some(jitter_max) = schedule.jitter_sec {
        let jitter = deterministic_jitter_secs(role, id, jitter_max);
        if jitter > 0 {
            log_msg(
                "INFO",
                "STARTUP",
                context,
                &format!(
                    "应用启动抖动 {} 秒以平滑连接洪峰（上限 {} 秒）。",
                    jitter, jitter_max
                ),
            );
            thread::sleep(Duration::from_secs(jitter));
        }
    }
}

fn deterministic_jitter_secs(role: &str, id: &str, max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    role.hash(&mut hasher);
    id.hash(&mut hasher);
    let range = max.saturating_add(1);
    let value = hasher.finish();
    if range == 0 {
        max
    } else {
        (value % range) as u64
    }
}

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
    let resolved_schedule = resolve_deployment_schedule(config.schedule.as_ref())?;

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

    if let Some(schedule) = &resolved_schedule {
        let iso = schedule.start_at.to_rfc3339_opts(SecondsFormat::Secs, true);
        let now = Utc::now();
        let delta = schedule.start_at.signed_duration_since(now).num_seconds();
        let timing_note = if delta > 0 {
            format!("距离当前时间约 {} 秒", delta)
        } else {
            format!("比当前时间早 {} 秒", -delta)
        };
        let jitter_note = schedule
            .jitter_sec
            .map(|j| format!(", 启动抖动 ≤ {} 秒", j))
            .unwrap_or_default();
        log_msg(
            "INFO",
            "DEPLOY",
            Some(String::from("CONFIG")),
            &format!(
                "统一启动时间: {} (允许时钟偏移 ±{} 秒{}，{}).",
                iso, schedule.max_drift_sec, jitter_note, timing_note
            ),
        );
    }

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
            .arg(node_cfg.node_id.clone())
            .arg(node_cfg.host.clone())
            .arg(node_cfg.port.to_string())
            .arg(bootstrap.clone())
            .arg(chunk_size.to_string())
            .arg(storage_bytes.to_string())
            .arg(bobtail_k.to_string())
            .env("P2P_SIM_CONFIG", config_json.clone());
        cmd.env_remove("BPST_STATIC_PEERS");
        if let Some(schedule) = &resolved_schedule {
            apply_schedule_env(&mut cmd, schedule);
        }
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
        if let Some(schedule) = &resolved_schedule {
            apply_schedule_env(&mut cmd, schedule);
        }
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
    wait_for_start_signal("NODE", &node_id);
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
    wait_for_start_signal("USER", &owner_id);
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
    wait_for_start_signal("OBSERVER", &observer_id);
    let _config = load_config_from_env();
    let observer = ObserverNode::new(observer_id, host, port, bootstrap, Duration::from_secs(60));
    observer.run();
}
