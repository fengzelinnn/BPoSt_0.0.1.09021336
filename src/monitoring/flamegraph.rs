use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Instant;

use chrono::{DateTime, Utc};
use flame::{self, SpanGuard};
use once_cell::sync::Lazy;
use parking_lot::Mutex;

#[derive(Clone, Default)]
struct ProfilerContext {
    node_id: Option<String>,
    user_id: Option<String>,
}

thread_local! {
    static CONTEXT_STACK: RefCell<Vec<ProfilerContext>> = RefCell::new(vec![ProfilerContext::default()]);
}

fn current_context() -> ProfilerContext {
    CONTEXT_STACK.with(|stack| stack.borrow().last().cloned().unwrap_or_default())
}

fn push_context(ctx: ProfilerContext) {
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

#[derive(Clone, Debug)]
pub struct PerfRecord {
    pub start_time: DateTime<Utc>,
    pub node_id: Option<String>,
    pub user_id: Option<String>,
    pub stack: Vec<String>,
    pub duration_ns: u128,
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

    pub fn clear(&self) {
        self.records.lock().clear();
        flame::clear();
    }

    pub fn export_collapsed(&self) -> std::io::Result<String> {
        let mut buffer = Vec::new();
        flame::dump_text_to_writer(&mut buffer)
            .map_err(|err| Error::new(ErrorKind::Other, err.to_string()))?;
        String::from_utf8(buffer).map_err(|err| Error::new(ErrorKind::InvalidData, err))
    }

    pub fn export_flamegraph_html(&self) -> std::io::Result<String> {
        if self.records.lock().is_empty() {
            return Ok(empty_flamegraph());
        }
        let mut buffer = Vec::new();
        flame::dump_html(&mut buffer)
            .map_err(|err| Error::new(ErrorKind::Other, err.to_string()))?;
        String::from_utf8(buffer).map_err(|err| Error::new(ErrorKind::InvalidData, err))
    }

    pub fn write_collapsed_to<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let path = path.as_ref();
        ensure_parent_directory(path)?;
        let collapsed = self.export_collapsed()?;
        std::fs::write(path, collapsed)
    }

    pub fn write_flamegraph_html_to<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let path = path.as_ref();
        ensure_parent_directory(path)?;
        let html = self.export_flamegraph_html()?;
        std::fs::write(path, html)
    }

    pub fn records(&self) -> Vec<PerfRecord> {
        self.records.lock().clone()
    }

    pub fn consensus_pressure_report(&self) -> Vec<(String, f64)> {
        let records = self.records.lock();
        PerfSummary::from_records(&*records).module_breakdown()
    }
}

fn is_target_module(stack: &[String]) -> bool {
    stack
        .first()
        .map(|label| matches!(label.as_str(), "dPDP" | "Folding" | "Nova"))
        .unwrap_or(false)
}

fn start_guards(stack: &[String], start_idx: usize) -> Vec<SpanGuard> {
    stack
        .iter()
        .skip(start_idx)
        .map(|label| flame::start_guard(label.clone()))
        .collect()
}

#[must_use = "performance span must be kept alive to record metrics"]
pub struct PerfSpan {
    monitor: &'static PerformanceMonitor,
    node_id: Option<String>,
    user_id: Option<String>,
    stack: Vec<String>,
    start_time: DateTime<Utc>,
    start_instant: Instant,
    guards: Vec<SpanGuard>,
    closed: bool,
    active: bool,
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
        let active_context = node_id.is_some() || user_id.is_some();
        let enabled = MONITOR_ENABLED.load(AtomicOrdering::Relaxed);
        let profile_target = is_target_module(&stack);
        let active = enabled && active_context && profile_target;
        let guards = if active {
            start_guards(&stack, 0)
        } else {
            Vec::new()
        };
        Self {
            monitor,
            node_id,
            user_id,
            stack,
            start_time,
            start_instant,
            guards,
            closed: false,
            active,
        }
    }

    pub fn child<I, L>(&self, labels: I) -> PerfSpan
    where
        I: IntoIterator<Item = L>,
        L: Into<String>,
    {
        let mut stack = self.stack.clone();
        stack.extend(labels.into_iter().map(|label| label.into()));
        let start_time = Utc::now();
        let start_instant = Instant::now();
        let active = self.active && is_target_module(&stack);
        let guards = if active {
            start_guards(&stack, self.stack.len())
        } else {
            Vec::new()
        };
        PerfSpan {
            monitor: self.monitor,
            node_id: self.node_id.clone(),
            user_id: self.user_id.clone(),
            stack,
            start_time,
            start_instant,
            guards,
            closed: false,
            active,
        }
    }

    pub fn finish(mut self) {
        self.close();
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        if !self.active {
            self.closed = true;
            return;
        }
        let duration = self.start_instant.elapsed().as_nanos();
        self.monitor.record(PerfRecord {
            start_time: self.start_time,
            node_id: self.node_id.clone(),
            user_id: self.user_id.clone(),
            stack: self.stack.clone(),
            duration_ns: duration,
        });
        while self.guards.pop().is_some() {}
        self.closed = true;
    }
}

impl Drop for PerfSpan {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct PerfContextGuard {
    pushed: bool,
    guards: Vec<SpanGuard>,
}

impl PerfContextGuard {
    pub fn new<N, U>(node_id: Option<N>, user_id: Option<U>) -> Self
    where
        N: Into<String>,
        U: Into<String>,
    {
        let node_id = node_id.map(|n| n.into());
        let user_id = user_id.map(|u| u.into());
        let context = ProfilerContext {
            node_id: node_id.clone(),
            user_id: user_id.clone(),
        };
        push_context(context);
        let enabled = MONITOR_ENABLED.load(AtomicOrdering::Relaxed);
        let active_context = node_id.is_some() || user_id.is_some();
        let mut guards = Vec::new();
        if enabled && active_context {
            if let Some(node) = &node_id {
                guards.push(flame::start_guard(format!("node:{}", node)));
            }
            if let Some(user) = &user_id {
                guards.push(flame::start_guard(format!("user:{}", user)));
            }
        }
        Self {
            pushed: true,
            guards,
        }
    }
}

impl Drop for PerfContextGuard {
    fn drop(&mut self) {
        if self.pushed {
            pop_context();
            self.pushed = false;
        }
        while self.guards.pop().is_some() {}
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
}

struct PerfSummary {
    rows: Vec<PerfSummaryRow>,
    total_duration_ns: u128,
}

impl PerfSummary {
    fn from_records(records: &[PerfRecord]) -> Self {
        let mut totals: BTreeMap<(String, String, String, String), PerfSummaryRow> =
            BTreeMap::new();
        let mut total_duration_ns = 0u128;

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

        rows.sort_by(|a, b| b.total_duration_ns.cmp(&a.total_duration_ns));

        PerfSummary {
            rows,
            total_duration_ns,
        }
    }

    fn module_breakdown(&self) -> Vec<(String, f64)> {
        if self.total_duration_ns == 0 {
            return Vec::new();
        }
        let mut breakdown: BTreeMap<String, u128> = BTreeMap::new();
        for row in &self.rows {
            let entry = breakdown.entry(row.module.clone()).or_insert(0);
            *entry = entry.saturating_add(row.total_duration_ns);
        }
        breakdown
            .into_iter()
            .map(|(module, total)| {
                let percentage = (total as f64 / self.total_duration_ns as f64) * 100.0;
                (module, percentage)
            })
            .collect()
    }
}

pub struct FlamegraphExportGuard {
    html_path: Option<PathBuf>,
    collapsed_path: Option<PathBuf>,
    clear_after: bool,
}

impl FlamegraphExportGuard {
    pub fn from_env() -> Self {
        let html_path = std::env::var("BPST_FLAME_HTML")
            .or_else(|_| std::env::var("BPST_PERF_FLAME"))
            .ok()
            .map(PathBuf::from);
        let collapsed_path = std::env::var("BPST_FLAME_COLLAPSED")
            .or_else(|_| std::env::var("BPST_PERF_CSV"))
            .ok()
            .map(PathBuf::from);
        let clear_after = std::env::var("BPST_FLAME_CLEAR")
            .or_else(|_| std::env::var("BPST_PERF_CLEAR"))
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        Self {
            html_path,
            collapsed_path,
            clear_after,
        }
    }

    pub fn new(
        html_path: Option<PathBuf>,
        collapsed_path: Option<PathBuf>,
        clear_after: bool,
    ) -> Self {
        Self {
            html_path,
            collapsed_path,
            clear_after,
        }
    }
}

impl Drop for FlamegraphExportGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.html_path {
            if let Err(err) = monitor().write_flamegraph_html_to(path) {
                eprintln!(
                    "failed to write flamegraph HTML {}: {}",
                    path.display(),
                    err
                );
            }
        }
        if let Some(path) = &self.collapsed_path {
            if let Err(err) = monitor().write_collapsed_to(path) {
                eprintln!(
                    "failed to write flamegraph collapsed stack {}: {}",
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
            let span = span(["dPDP", "operation"]);
            {
                let _child = span.child(["sub"]);
            }
            span.finish();
        }
        let records = monitor().records();
        assert!(records
            .iter()
            .any(|rec| rec.stack.contains(&"dPDP".to_string())));
        assert!(records
            .iter()
            .any(|rec| rec.node_id.as_deref() == Some("node-test")));
    }

    #[test]
    fn exports_html_flamegraph() {
        monitor().clear();
        {
            let _ctx = enter_context(Some("node-a".to_string()), Some("user-a".to_string()));
            let _span = span(["dPDP", "unit"]);
        }
        let html = monitor().export_flamegraph_html().expect("html output");
        assert!(html.contains("<html"));
        monitor().clear();
    }

    #[test]
    fn consensus_pressure_reports_root_labels() {
        monitor().clear();
        {
            let _ctx = enter_context(
                Some("node-consensus".to_string()),
                Some("user-consensus".to_string()),
            );
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
        }

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
}
