use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use parking_lot::Mutex;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct PerfKey {
    node_id: Option<String>,
    user_id: Option<String>,
    operation_segments: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct PerfStats {
    calls: u64,
    total_duration: Duration,
    total_cycles: u128,
    cycle_samples: u64,
}

impl PerfStats {
    fn record(&mut self, duration: Duration, cycles: Option<u64>) {
        self.calls = self.calls.saturating_add(1);
        self.total_duration += duration;
        if let Some(value) = cycles {
            self.total_cycles = self.total_cycles.saturating_add(value as u128);
            self.cycle_samples = self.cycle_samples.saturating_add(1);
        }
    }
}

/// 聚合后的性能记录行。
#[derive(Clone, Debug)]
pub struct PerfReportRow {
    pub node_id: Option<String>,
    pub user_id: Option<String>,
    pub operation_segments: Vec<String>,
    pub calls: u64,
    pub total_duration: Duration,
    pub total_cycles: u128,
    pub cycle_samples: u64,
}

impl PerfReportRow {
    /// 返回 `op1::op2::op3` 风格的操作路径。
    pub fn operation_path(&self) -> String {
        self.operation_segments.join("::")
    }
}

/// 性能监控器，负责记录和导出 dPDP / Nova 折叠相关操作的性能数据。
pub struct PerformanceMonitor {
    inner: Mutex<HashMap<PerfKey, PerfStats>>,
}

static GLOBAL_MONITOR: Lazy<PerformanceMonitor> = Lazy::new(PerformanceMonitor::new);

impl PerformanceMonitor {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// 全局唯一的性能监控器实例。
    pub fn global() -> &'static Self {
        &GLOBAL_MONITOR
    }

    /// 进入一个性能监控作用域，返回 RAII guard。
    pub fn enter(
        &'static self,
        node_id: Option<&str>,
        user_id: Option<&str>,
        segments: &[&str],
    ) -> PerfGuard {
        let key = PerfKey {
            node_id: node_id.map(|id| id.to_string()),
            user_id: user_id.map(|id| id.to_string()),
            operation_segments: segments.iter().map(|s| s.to_string()).collect(),
        };
        PerfGuard::new(self, key)
    }

    fn enter_with_key(&'static self, key: PerfKey) -> PerfGuard {
        PerfGuard::new(self, key)
    }

    fn record_observation(&self, key: PerfKey, duration: Duration, cycles: Option<u64>) {
        let mut inner = self.inner.lock();
        let stats = inner.entry(key).or_default();
        stats.record(duration, cycles);
    }

    /// 生成当前的快照数据。
    pub fn snapshot(&self) -> Vec<PerfReportRow> {
        let mut rows: Vec<_> = self
            .inner
            .lock()
            .iter()
            .map(|(key, stats)| PerfReportRow {
                node_id: key.node_id.clone(),
                user_id: key.user_id.clone(),
                operation_segments: key.operation_segments.clone(),
                calls: stats.calls,
                total_duration: stats.total_duration,
                total_cycles: stats.total_cycles,
                cycle_samples: stats.cycle_samples,
            })
            .collect();
        rows.sort_by(|a, b| compare_rows(a, b));
        rows
    }

    /// 清空已有的监控数据。
    pub fn clear(&self) {
        self.inner.lock().clear();
    }

    /// 将快照写出为 CSV。
    pub fn write_csv<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writeln!(
            writer,
            "node_id,user_id,operation_path,calls,total_micros,avg_micros,total_cycles,avg_cycles"
        )?;
        for row in self.snapshot() {
            let total_micros = row.total_duration.as_micros();
            let avg_micros = if row.calls > 0 {
                total_micros / row.calls as u128
            } else {
                0
            };
            let (total_cycles, avg_cycles) = if row.cycle_samples > 0 {
                let avg = row.total_cycles / row.cycle_samples as u128;
                (row.total_cycles.to_string(), avg.to_string())
            } else {
                (String::new(), String::new())
            };
            writeln!(
                writer,
                "{},{},{},{},{},{},{},{}",
                row.node_id.as_deref().unwrap_or(""),
                row.user_id.as_deref().unwrap_or(""),
                row.operation_path(),
                row.calls,
                total_micros,
                avg_micros,
                total_cycles,
                avg_cycles
            )?;
        }
        Ok(())
    }

    /// 按照 FlameGraph collapsed stack 的格式导出时长和 cycles。
    pub fn write_collapsed_flamegraph<W: Write>(&self, mut writer: W) -> io::Result<()> {
        for row in self.snapshot() {
            let mut stack = Vec::new();
            if let Some(node) = &row.node_id {
                stack.push(format!("node:{}", node));
            }
            if let Some(user) = &row.user_id {
                stack.push(format!("user:{}", user));
            }
            stack.extend(row.operation_segments.iter().cloned());
            let frame = stack.join(";");
            let duration_value = row.total_duration.as_micros();
            if duration_value > 0 {
                writeln!(writer, "{} {}", frame, duration_value)?;
            }
            if row.cycle_samples > 0 && row.total_cycles > 0 {
                let mut cycle_stack = stack.clone();
                cycle_stack.push(String::from("[cycles]"));
                writeln!(writer, "{} {}", cycle_stack.join(";"), row.total_cycles)?;
            }
        }
        Ok(())
    }

    /// 保存 CSV 报告到文件。
    pub fn save_csv<P: AsRef<Path>>(&self, path: P) -> io::Result<PathBuf> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut file = File::create(path)?;
        self.write_csv(&mut file)?;
        Ok(path.to_path_buf())
    }

    /// 保存 collapsed stack 报告到文件。
    pub fn save_collapsed_flamegraph<P: AsRef<Path>>(&self, path: P) -> io::Result<PathBuf> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut file = File::create(path)?;
        self.write_collapsed_flamegraph(&mut file)?;
        Ok(path.to_path_buf())
    }

    /// 同时保存 CSV 与 FlameGraph 两种格式，返回文件路径。
    pub fn save_reports<P: AsRef<Path>>(
        &self,
        dir: P,
        prefix: &str,
    ) -> io::Result<(PathBuf, PathBuf)> {
        let sanitized = sanitize_prefix(prefix);
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;
        let csv_path = dir.join(format!("{}_performance.csv", sanitized));
        let flame_path = dir.join(format!("{}_performance.collapsed", sanitized));
        let csv = self.save_csv(csv_path)?;
        let flame = self.save_collapsed_flamegraph(flame_path)?;
        Ok((csv, flame))
    }
}

fn compare_rows(a: &PerfReportRow, b: &PerfReportRow) -> Ordering {
    let node_cmp = a
        .node_id
        .as_deref()
        .unwrap_or("")
        .cmp(b.node_id.as_deref().unwrap_or(""));
    if node_cmp != Ordering::Equal {
        return node_cmp;
    }
    let user_cmp = a
        .user_id
        .as_deref()
        .unwrap_or("")
        .cmp(b.user_id.as_deref().unwrap_or(""));
    if user_cmp != Ordering::Equal {
        return user_cmp;
    }
    a.operation_segments.cmp(&b.operation_segments)
}

fn sanitize_prefix(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' => c,
            _ => '_',
        })
        .collect()
}

fn read_cpu_cycles() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: _rdtsc 只读取时间戳计数器，不会产生未定义行为。
        Some(unsafe { core::arch::x86_64::_rdtsc() })
    }
    #[cfg(target_arch = "x86")]
    {
        // SAFETY: _rdtsc 只读取时间戳计数器，不会产生未定义行为。
        Some(unsafe { core::arch::x86::_rdtsc() as u64 })
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        None
    }
}

/// RAII guard，用于在作用域结束时记录性能数据。
pub struct PerfGuard {
    monitor: &'static PerformanceMonitor,
    key: PerfKey,
    start: Instant,
    start_cycles: Option<u64>,
    active: bool,
}

impl PerfGuard {
    fn new(monitor: &'static PerformanceMonitor, key: PerfKey) -> Self {
        Self {
            monitor,
            key,
            start: Instant::now(),
            start_cycles: read_cpu_cycles(),
            active: true,
        }
    }

    /// 从当前 guard 派生子操作，沿用节点/用户上下文并追加路径。
    pub fn child(&self, segments: &[&str]) -> PerfGuard {
        let mut combined = self.key.operation_segments.clone();
        combined.extend(segments.iter().map(|s| s.to_string()));
        let child_key = PerfKey {
            node_id: self.key.node_id.clone(),
            user_id: self.key.user_id.clone(),
            operation_segments: combined,
        };
        self.monitor.enter_with_key(child_key)
    }

    /// 主动终止记录，用于异常路径。
    pub fn cancel(mut self) {
        self.active = false;
    }
}

impl Drop for PerfGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let duration = self.start.elapsed();
        let cycles = self
            .start_cycles
            .and_then(|start| read_cpu_cycles().map(|end| end.wrapping_sub(start)));
        self.monitor
            .record_observation(self.key.clone(), duration, cycles);
    }
}

/// 简化函数，直接基于全局监控器进入一个性能作用域。
pub fn perf_scope(node_id: Option<&str>, user_id: Option<&str>, segments: &[&str]) -> PerfGuard {
    PerformanceMonitor::global().enter(node_id, user_id, segments)
}
