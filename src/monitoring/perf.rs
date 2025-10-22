use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::{Cursor, Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Instant;

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use parking_lot::Mutex;

use inferno::flamegraph::{from_reader, Options};

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{BOOL, HANDLE};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::GetCurrentThread;

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn QueryThreadCycleTime(ThreadHandle: HANDLE, CycleTime: *mut u64) -> BOOL;
}

#[derive(Clone, Default)]
struct PerfContext {
    node_id: Option<String>,
    user_id: Option<String>,
}

thread_local! {
    static CONTEXT_STACK: RefCell<Vec<PerfContext>> = RefCell::new(vec![PerfContext::default()]);
}

fn current_context() -> PerfContext {
    CONTEXT_STACK.with(|stack| stack.borrow().last().cloned().unwrap_or_default())
}

fn push_context(ctx: PerfContext) {
    CONTEXT_STACK.with(|stack| stack.borrow_mut().push(ctx));
}

fn pop_context() {
    CONTEXT_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        if stack.len() > 1 {
            stack.pop();
        }
    });
}

fn read_cpu_cycles() -> Option<u64> {
    #[cfg(target_os = "windows")]
    {
        unsafe {
            let mut cycles: u64 = 0;
            let handle = GetCurrentThread();
            let result: BOOL = QueryThreadCycleTime(handle, &mut cycles);
            if result.as_bool() {
                Some(cycles)
            } else {
                None
            }
        }
    }
    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    {
        // Safety: _rdtsc has no safety requirements beyond running on x86/x86_64.
        Some(unsafe { core::arch::x86_64::_rdtsc() })
    }
    #[cfg(all(not(target_os = "windows"), target_arch = "x86"))]
    {
        Some(unsafe { core::arch::x86::_rdtsc() })
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        None
    }
}

#[derive(Clone, Debug)]
pub struct PerfRecord {
    pub start_time: DateTime<Utc>,
    pub node_id: Option<String>,
    pub user_id: Option<String>,
    pub stack: Vec<String>,
    pub duration_ns: u128,
    pub cpu_cycles: Option<u64>,
}

#[derive(Default)]
pub struct PerformanceMonitor {
    records: Mutex<Vec<PerfRecord>>,
}

static PERFORMANCE_MONITOR: Lazy<PerformanceMonitor> = Lazy::new(PerformanceMonitor::default);
static MONITOR_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn monitor() -> &'static PerformanceMonitor {
    &PERFORMANCE_MONITOR
}

impl PerformanceMonitor {
    pub fn start_span<I, L>(&'static self, labels: I) -> PerfSpan
    where
        I: IntoIterator<Item = L>,
        L: Into<String>,
    {
        self.start_span_with_context(None::<String>, None::<String>, labels)
    }

    pub fn start_span_with_context<I, L, N, U>(
        &'static self,
        node_id: Option<N>,
        user_id: Option<U>,
        labels: I,
    ) -> PerfSpan
    where
        I: IntoIterator<Item = L>,
        L: Into<String>,
        N: Into<String>,
        U: Into<String>,
    {
        let context = current_context();
        let node_id = node_id
            .map(|n| n.into())
            .or_else(|| context.node_id.clone());
        let user_id = user_id
            .map(|u| u.into())
            .or_else(|| context.user_id.clone());
        PerfSpan::new(
            self,
            node_id,
            user_id,
            labels.into_iter().map(|label| label.into()).collect(),
        )
    }

    pub fn record(&self, record: PerfRecord) {
        if !MONITOR_ENABLED.load(AtomicOrdering::Relaxed) {
            return;
        }
        self.records.lock().push(record);
    }

    pub fn set_enabled(&self, enabled: bool) {
        MONITOR_ENABLED.store(enabled, AtomicOrdering::SeqCst);
    }

    pub fn scoped_disable(&'static self) -> PerfDisableGuard {
        let previous = MONITOR_ENABLED.swap(false, AtomicOrdering::SeqCst);
        PerfDisableGuard::new(previous)
    }

    pub fn export_csv(&self) -> String {
        let records = self.records.lock();
        let summary = PerfSummary::from_records(&*records);
        summary.to_csv()
    }

    pub fn consensus_pressure_report(&self) -> Vec<(String, f64)> {
        let records = self.records.lock();
        PerfSummary::from_records(&*records).module_breakdown()
    }

    fn collapsed_stacks(records: &[PerfRecord]) -> Vec<(String, u128)> {
        let mut aggregated: BTreeMap<String, u128> = BTreeMap::new();
        for record in records.iter() {
            let mut stack = Vec::new();
            if let Some(node) = &record.node_id {
                stack.push(format!("node:{}", node));
            }
            if let Some(user) = &record.user_id {
                stack.push(format!("user:{}", user));
            }
            if record.stack.is_empty() {
                stack.push("unknown".to_string());
            } else {
                stack.extend(record.stack.iter().cloned());
            }
            let duration = record.duration_ns.max(1);
            let entry = aggregated.entry(stack.join(";")).or_insert(0);
            *entry = entry.saturating_add(duration);
        }
        aggregated.into_iter().collect()
    }

    pub fn export_collapsed_flamegraph(&self) -> String {
        let records = self.records.lock().clone();
        let mut out = String::new();
        for (stack, duration) in Self::collapsed_stacks(&records) {
            out.push_str(&format!("{} {}\n", stack, duration));
        }
        out
    }

    pub fn export_flamegraph_svg(&self) -> std::io::Result<String> {
        let records = self.records.lock().clone();
        if records.is_empty() {
            return Ok(empty_flamegraph());
        }
        let mut options = Options::default();
        options.count_name = "ns".to_string();
        let collapsed = {
            let mut out = String::new();
            for (stack, duration) in Self::collapsed_stacks(&records) {
                out.push_str(&format!("{} {}\n", stack, duration));
            }
            out
        };
        let mut reader = Cursor::new(collapsed);
        let mut output = Vec::new();
        from_reader(&mut options, &mut reader, &mut output)
            .map_err(|err| Error::new(ErrorKind::Other, err.to_string()))?;
        String::from_utf8(output).map_err(|err| Error::new(ErrorKind::InvalidData, err))
    }

    pub fn write_csv_to<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let path = path.as_ref();
        ensure_parent_directory(path)?;
        std::fs::write(path, self.export_csv())
    }

    pub fn write_flamegraph_to<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let path = path.as_ref();
        ensure_parent_directory(path)?;
        let svg = self.export_flamegraph_svg()?;
        std::fs::write(path, svg)
    }

    pub fn clear(&self) {
        self.records.lock().clear();
    }

    pub fn records(&self) -> Vec<PerfRecord> {
        self.records.lock().clone()
    }
}

#[must_use = "performance span must be kept alive to record metrics"]
pub struct PerfSpan {
    monitor: &'static PerformanceMonitor,
    node_id: Option<String>,
    user_id: Option<String>,
    stack: Vec<String>,
    start_time: DateTime<Utc>,
    start_instant: Instant,
    start_cycles: Option<u64>,
    closed: bool,
}

impl PerfSpan {
    fn new(
        monitor: &'static PerformanceMonitor,
        node_id: Option<String>,
        user_id: Option<String>,
        stack: Vec<String>,
    ) -> Self {
        let start_time = Utc::now();
        let start_instant = Instant::now();
        let start_cycles = read_cpu_cycles();
        Self {
            monitor,
            node_id,
            user_id,
            stack,
            start_time,
            start_instant,
            start_cycles,
            closed: false,
        }
    }

    pub fn child<I, L>(&self, labels: I) -> PerfSpan
    where
        I: IntoIterator<Item = L>,
        L: Into<String>,
    {
        let mut stack = self.stack.clone();
        stack.extend(labels.into_iter().map(|label| label.into()));
        PerfSpan::new(
            self.monitor,
            self.node_id.clone(),
            self.user_id.clone(),
            stack,
        )
    }

    pub fn finish(mut self) {
        self.close();
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        if !MONITOR_ENABLED.load(AtomicOrdering::Relaxed) {
            self.closed = true;
            return;
        }
        let duration = self.start_instant.elapsed().as_nanos();
        let end_cycles = read_cpu_cycles();
        let cpu_cycles = match (self.start_cycles, end_cycles) {
            (Some(start), Some(end)) => Some(end.saturating_sub(start)),
            _ => None,
        };
        self.monitor.record(PerfRecord {
            start_time: self.start_time,
            node_id: self.node_id.clone(),
            user_id: self.user_id.clone(),
            stack: self.stack.clone(),
            duration_ns: duration,
            cpu_cycles,
        });
        self.closed = true;
    }
}

impl Drop for PerfSpan {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct PerfContextGuard {
    active: bool,
}

impl PerfContextGuard {
    pub fn new<N, U>(node_id: Option<N>, user_id: Option<U>) -> Self
    where
        N: Into<String>,
        U: Into<String>,
    {
        let ctx = PerfContext {
            node_id: node_id.map(|n| n.into()),
            user_id: user_id.map(|u| u.into()),
        };
        push_context(ctx);
        Self { active: true }
    }
}

impl Drop for PerfContextGuard {
    fn drop(&mut self) {
        if self.active {
            pop_context();
            self.active = false;
        }
    }
}

pub struct PerfExportGuard {
    csv_path: Option<PathBuf>,
    flame_path: Option<PathBuf>,
    clear_after: bool,
}

impl PerfExportGuard {
    pub fn from_env() -> Self {
        let csv_path = std::env::var("BPST_PERF_CSV").ok().map(PathBuf::from);
        let flame_path = std::env::var("BPST_PERF_FLAME").ok().map(PathBuf::from);
        let clear_after = std::env::var("BPST_PERF_CLEAR")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        Self {
            csv_path,
            flame_path,
            clear_after,
        }
    }

    pub fn new(csv_path: Option<PathBuf>, flame_path: Option<PathBuf>, clear_after: bool) -> Self {
        Self {
            csv_path,
            flame_path,
            clear_after,
        }
    }
}

impl Drop for PerfExportGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.csv_path {
            if let Err(err) = monitor().write_csv_to(path) {
                eprintln!(
                    "failed to write performance CSV {}: {}",
                    path.display(),
                    err
                );
            }
        }
        if let Some(path) = &self.flame_path {
            if let Err(err) = monitor().write_flamegraph_to(path) {
                eprintln!(
                    "failed to write performance flamegraph {}: {}",
                    path.display(),
                    err
                );
            }
        }
        if self.clear_after {
            monitor().clear();
        }
    }
}

pub fn enter_context<N, U>(node_id: Option<N>, user_id: Option<U>) -> PerfContextGuard
where
    N: Into<String>,
    U: Into<String>,
{
    PerfContextGuard::new(node_id, user_id)
}

pub fn span<I, L>(labels: I) -> PerfSpan
where
    I: IntoIterator<Item = L>,
    L: Into<String>,
{
    monitor().start_span(labels)
}

pub fn span_with_context<I, L, N, U>(node_id: Option<N>, user_id: Option<U>, labels: I) -> PerfSpan
where
    I: IntoIterator<Item = L>,
    L: Into<String>,
    N: Into<String>,
    U: Into<String>,
{
    monitor().start_span_with_context(node_id, user_id, labels)
}

pub struct PerfDisableGuard {
    previous: bool,
}

impl PerfDisableGuard {
    fn new(previous: bool) -> Self {
        Self { previous }
    }
}

impl Drop for PerfDisableGuard {
    fn drop(&mut self) {
        MONITOR_ENABLED.store(self.previous, AtomicOrdering::SeqCst);
    }
}

#[derive(Clone, Default)]
struct PerfSummaryRow {
    node_id: String,
    user_id: String,
    module: String,
    operation: String,
    count: u64,
    total_duration_ns: u128,
    total_cycles: u128,
}

struct PerfSummary {
    rows: Vec<PerfSummaryRow>,
    total_duration_ns: u128,
    total_cycles: u128,
    has_cycles: bool,
}

impl PerfSummary {
    fn from_records(records: &[PerfRecord]) -> Self {
        let mut totals: BTreeMap<(String, String, String, String), PerfSummaryRow> =
            BTreeMap::new();
        let mut total_duration_ns = 0u128;
        let mut total_cycles = 0u128;
        let mut has_cycles = false;

        for record in records {
            let node_id = record.node_id.clone().unwrap_or_else(|| "-".to_string());
            let user_id = record.user_id.clone().unwrap_or_else(|| "-".to_string());
            let module = record
                .stack
                .first()
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let operation = if record.stack.len() > 1 {
                record.stack[1..].join("::")
            } else {
                "-".to_string()
            };
            let key = (node_id, user_id, module, operation);
            let entry = totals.entry(key).or_insert_with(PerfSummaryRow::default);
            entry.count = entry.count.saturating_add(1);
            entry.total_duration_ns = entry.total_duration_ns.saturating_add(record.duration_ns);
            if let Some(cycles) = record.cpu_cycles {
                has_cycles = true;
                let cycles = cycles as u128;
                entry.total_cycles = entry.total_cycles.saturating_add(cycles);
                total_cycles = total_cycles.saturating_add(cycles);
            }
            total_duration_ns = total_duration_ns.saturating_add(record.duration_ns);
        }

        let mut rows: Vec<PerfSummaryRow> = totals
            .into_iter()
            .map(|((node_id, user_id, module, operation), mut row)| {
                row.node_id = node_id;
                row.user_id = user_id;
                row.module = module;
                row.operation = operation;
                row
            })
            .collect();

        rows.sort_by(|a, b| {
            let metric_a = if has_cycles && total_cycles > 0 {
                a.total_cycles
            } else {
                a.total_duration_ns
            };
            let metric_b = if has_cycles && total_cycles > 0 {
                b.total_cycles
            } else {
                b.total_duration_ns
            };
            metric_b
                .cmp(&metric_a)
                .then_with(|| a.module.cmp(&b.module))
                .then_with(|| a.operation.cmp(&b.operation))
                .then_with(|| a.node_id.cmp(&b.node_id))
                .then_with(|| a.user_id.cmp(&b.user_id))
        });

        Self {
            rows,
            total_duration_ns,
            total_cycles,
            has_cycles,
        }
    }

    fn to_csv(&self) -> String {
        let mut csv = String::from(
            "node_id,user_id,module,operation,count,total_duration_ns,total_cycles,percent_duration,percent_cycles\n",
        );
        for row in &self.rows {
            let percent_duration = if self.total_duration_ns > 0 {
                (row.total_duration_ns as f64 / self.total_duration_ns as f64) * 100.0
            } else {
                0.0
            };
            let percent_cycles = if self.has_cycles && self.total_cycles > 0 {
                Some((row.total_cycles as f64 / self.total_cycles as f64) * 100.0)
            } else {
                None
            };
            let operation = if row.operation.trim().is_empty() {
                "-"
            } else {
                &row.operation
            };
            let cycles_value = if self.has_cycles {
                row.total_cycles.to_string()
            } else {
                "-".to_string()
            };
            let percent_cycles_value = percent_cycles
                .map(|value| format!("{value:.4}"))
                .unwrap_or_else(|| "-".to_string());
            let percent_duration_value = if self.total_duration_ns > 0 {
                format!("{percent_duration:.4}")
            } else {
                "-".to_string()
            };
            csv.push_str(&format!(
                "{node},{user},{module},{operation},{count},{duration},{cycles},{percent_duration},{percent_cycles}\n",
                node = row.node_id,
                user = row.user_id,
                module = row.module,
                operation = operation,
                count = row.count,
                duration = row.total_duration_ns,
                cycles = cycles_value,
                percent_duration = percent_duration_value,
                percent_cycles = percent_cycles_value,
            ));
        }
        csv
    }

    fn module_breakdown(&self) -> Vec<(String, f64)> {
        if self.rows.is_empty() {
            return Vec::new();
        }
        let mut totals: BTreeMap<String, u128> = BTreeMap::new();
        for row in &self.rows {
            let metric = if self.has_cycles && self.total_cycles > 0 {
                row.total_cycles
            } else {
                row.total_duration_ns
            };
            if metric == 0 {
                continue;
            }
            let entry = totals.entry(row.module.clone()).or_insert(0);
            *entry = entry.saturating_add(metric);
        }
        let total_metric = if self.has_cycles && self.total_cycles > 0 {
            self.total_cycles
        } else {
            self.total_duration_ns
        };
        if total_metric == 0 {
            return Vec::new();
        }
        let mut breakdown: Vec<(String, f64)> = totals
            .into_iter()
            .map(|(module, total)| {
                let share = (total as f64 / total_metric as f64) * 100.0;
                (module, share)
            })
            .collect();
        breakdown.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        breakdown
    }
}

fn ensure_parent_directory(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn empty_flamegraph() -> String {
    [
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"600\" height=\"80\">",
        "  <rect width=\"600\" height=\"80\" fill=\"#1f2933\"/>",
        "  <text x=\"20\" y=\"45\" fill=\"#f9fafb\" font-family=\"monospace\" font-size=\"16\">No performance samples collected</text>",
        "</svg>",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::dpdp::DPDP;
    use std::collections::HashMap;

    #[test]
    fn records_span_duration_and_stack() {
        monitor().clear();
        {
            let _ctx = enter_context(Some("node-test".to_string()), None::<String>);
            let span = span(["module", "operation"]);
            {
                let _child = span.child(vec![String::from("sub")]);
            }
            span.finish();
        }
        let records = monitor().records();
        assert!(records
            .iter()
            .any(|rec| rec.stack.contains(&"module".to_string())));
        assert!(records
            .iter()
            .any(|rec| rec.node_id.as_deref() == Some("node-test")));
    }

    #[test]
    fn exports_svg_flamegraph() {
        monitor().clear();
        {
            let _ctx = enter_context(Some("node-a".to_string()), Some("user-a".to_string()));
            let _span = span(["task", "unit"]);
        }
        let svg = monitor().export_flamegraph_svg().expect("svg output");
        assert!(svg.contains("<svg"));
    }

    #[test]
    fn consensus_pressure_reports_root_labels() {
        monitor().clear();
        let params = DPDP::key_gen();
        let chunks: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8; 128]).collect();
        let tags = DPDP::tag_file(&params, &chunks);
        let challenge = DPDP::gen_chal("seed", 42, &tags, Some(4));
        let mut chunk_map: HashMap<usize, Vec<u8>> = HashMap::new();
        for (i, chunk) in chunks.iter().enumerate() {
            chunk_map.insert(i, chunk.clone());
        }
        let proof = DPDP::gen_proof(&tags, &chunk_map, &challenge);
        let _ = DPDP::check_proof_with_relaxed(&params, &proof, &challenge);

        let breakdown = monitor().consensus_pressure_report();
        assert!(breakdown
            .iter()
            .any(|(label, share)| label == "dPDP" && *share > 0.0));
        assert!(breakdown
            .iter()
            .any(|(label, share)| label == "Folding" && *share > 0.0));
        let total_share: f64 = breakdown.iter().map(|(_, share)| share).sum();
        assert!(total_share > 0.0);
        monitor().clear();
    }

    #[test]
    fn consensus_pressure_prefers_cpu_cycles_when_available() {
        monitor().clear();
        let now = Utc::now();
        monitor().record(PerfRecord {
            start_time: now,
            node_id: None,
            user_id: None,
            stack: vec!["alpha".to_string()],
            duration_ns: 10,
            cpu_cycles: Some(10),
        });
        monitor().record(PerfRecord {
            start_time: now,
            node_id: None,
            user_id: None,
            stack: vec!["beta".to_string()],
            duration_ns: 10_000,
            cpu_cycles: Some(10),
        });

        let breakdown = monitor().consensus_pressure_report();
        assert_eq!(breakdown.len(), 2);
        let alpha_share = breakdown
            .iter()
            .find(|(label, _)| label == "alpha")
            .map(|(_, share)| *share)
            .unwrap();
        let beta_share = breakdown
            .iter()
            .find(|(label, _)| label == "beta")
            .map(|(_, share)| *share)
            .unwrap();
        assert!((alpha_share - beta_share).abs() < f64::EPSILON);
        monitor().clear();
    }
}
