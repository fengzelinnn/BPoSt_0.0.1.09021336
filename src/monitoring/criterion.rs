use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use chrono::{DateTime, Utc};
use criterion::measurement::Measurement;
use criterion::measurement::WallTime;
use once_cell::sync::Lazy;
use parking_lot::Mutex;

#[derive(Clone, Default)]
struct MonitorContext {
    node_id: Option<String>,
    user_id: Option<String>,
}

thread_local! {
    static CONTEXT_STACK: RefCell<Vec<MonitorContext>> = RefCell::new(vec![MonitorContext::default()]);
}

fn current_context() -> MonitorContext {
    CONTEXT_STACK
        .with(|stack| stack.borrow().last().cloned())
        .unwrap_or_default()
}

fn push_context(ctx: MonitorContext) {
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
pub struct BenchmarkRecord {
    pub start_time: DateTime<Utc>,
    pub node_id: Option<String>,
    pub user_id: Option<String>,
    pub stack: Vec<String>,
    pub duration_ns: u128,
}

#[derive(Default)]
pub struct CriterionMonitor {
    records: Mutex<Vec<BenchmarkRecord>>,
}

static MONITOR_ENABLED: AtomicBool = AtomicBool::new(true);
static CRITERION_MONITOR: Lazy<CriterionMonitor> = Lazy::new(CriterionMonitor::default);

pub fn monitor() -> &'static CriterionMonitor {
    &CRITERION_MONITOR
}

impl CriterionMonitor {
    pub fn start_span<I, L>(&'static self, labels: I) -> CriterionSpan
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
    ) -> CriterionSpan
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
        CriterionSpan::new(
            self,
            node_id,
            user_id,
            labels.into_iter().map(|label| label.into()).collect(),
        )
    }

    pub fn record(&self, record: BenchmarkRecord) {
        if !MONITOR_ENABLED.load(AtomicOrdering::Relaxed) {
            return;
        }
        self.records.lock().push(record);
    }

    pub fn set_enabled(&self, enabled: bool) {
        MONITOR_ENABLED.store(enabled, AtomicOrdering::SeqCst);
    }

    pub fn scoped_disable(&'static self) -> CriterionDisableGuard {
        let previous = MONITOR_ENABLED.swap(false, AtomicOrdering::SeqCst);
        CriterionDisableGuard::new(previous)
    }

    pub fn export_csv(&self) -> String {
        let records = self.records.lock();
        let summary = CriterionSummary::from_records(&records);
        summary.to_csv()
    }

    pub fn export_summary_json(&self) -> String {
        let records = self.records.lock();
        let summary = CriterionSummary::from_records(&records);
        summary.to_json()
    }

    pub fn consensus_pressure_report(&self) -> Vec<(String, f64)> {
        let records = self.records.lock();
        CriterionSummary::from_records(&records).module_breakdown()
    }

    pub fn total_duration_ns(&self) -> u128 {
        let records = self.records.lock();
        CriterionSummary::from_records(&records).total_duration_ns
    }

    pub fn consensus_operation_stats(&self) -> Vec<ConsensusOperationStat> {
        let records = self.records.lock();
        CriterionSummary::from_records(&records).consensus_operation_stats()
    }

    pub fn write_csv_to<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let path = path.as_ref();
        ensure_parent_directory(path)?;
        fs::write(path, self.export_csv())
    }

    pub fn write_summary_to<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let path = path.as_ref();
        ensure_parent_directory(path)?;
        fs::write(path, self.export_summary_json())
    }

    pub fn clear(&self) {
        self.records.lock().clear();
    }

    pub fn records(&self) -> Vec<BenchmarkRecord> {
        self.records.lock().clone()
    }
}

#[must_use = "benchmark span must be kept alive to record metrics"]
pub struct CriterionSpan {
    monitor: &'static CriterionMonitor,
    node_id: Option<String>,
    user_id: Option<String>,
    stack: Vec<String>,
    start_time: DateTime<Utc>,
    measurement: WallTime,
    start_intermediate: <WallTime as Measurement>::Intermediate,
    closed: bool,
}

impl CriterionSpan {
    fn new(
        monitor: &'static CriterionMonitor,
        node_id: Option<String>,
        user_id: Option<String>,
        stack: Vec<String>,
    ) -> Self {
        let measurement = WallTime;
        let start_intermediate = measurement.start();
        Self {
            monitor,
            node_id,
            user_id,
            stack,
            start_time: Utc::now(),
            measurement,
            start_intermediate,
            closed: false,
        }
    }

    pub fn child<I, L>(&self, labels: I) -> CriterionSpan
    where
        I: IntoIterator<Item = L>,
        L: Into<String>,
    {
        let mut stack = self.stack.clone();
        stack.extend(labels.into_iter().map(|label| label.into()));
        CriterionSpan::new(
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
        let duration = self.measurement.end(self.start_intermediate);
        self.monitor.record(BenchmarkRecord {
            start_time: self.start_time,
            node_id: self.node_id.clone(),
            user_id: self.user_id.clone(),
            stack: self.stack.clone(),
            duration_ns: duration.as_nanos(),
        });
        self.closed = true;
    }
}

impl Drop for CriterionSpan {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct CriterionContextGuard {
    active: bool,
}

impl CriterionContextGuard {
    pub fn new<N, U>(node_id: Option<N>, user_id: Option<U>) -> Self
    where
        N: Into<String>,
        U: Into<String>,
    {
        let ctx = MonitorContext {
            node_id: node_id.map(|n| n.into()),
            user_id: user_id.map(|u| u.into()),
        };
        push_context(ctx);
        Self { active: true }
    }
}

impl Drop for CriterionContextGuard {
    fn drop(&mut self) {
        if self.active {
            pop_context();
            self.active = false;
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConsensusOperationStat {
    pub operation: String,
    pub total_duration_ns: u128,
    pub share_of_total: f64,
}

pub struct CriterionExportGuard {
    csv_path: Option<PathBuf>,
    summary_path: Option<PathBuf>,
    estimates_output_dir: Option<PathBuf>,
    clear_after: bool,
}

impl CriterionExportGuard {
    pub fn from_env() -> Self {
        let csv_path = std::env::var("BPST_CRITERION_CSV").ok().map(PathBuf::from);
        let summary_path = std::env::var("BPST_CRITERION_JSON").ok().map(PathBuf::from);
        let clear_after = std::env::var("BPST_CRITERION_CLEAR")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        let estimates_output_dir = std::env::var("BPST_CRITERION_ESTIMATES_DIR")
            .ok()
            .map(PathBuf::from);
        Self {
            csv_path,
            summary_path,
            estimates_output_dir,
            clear_after,
        }
    }

    pub fn new(
        csv_path: Option<PathBuf>,
        summary_path: Option<PathBuf>,
        estimates_output_dir: Option<PathBuf>,
        clear_after: bool,
    ) -> Self {
        Self {
            csv_path,
            summary_path,
            estimates_output_dir,
            clear_after,
        }
    }
}

impl Drop for CriterionExportGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.csv_path {
            if let Err(err) = monitor().write_csv_to(path) {
                eprintln!("failed to write criterion CSV {}: {}", path.display(), err);
            }
        }
        if let Some(path) = &self.summary_path {
            if let Err(err) = monitor().write_summary_to(path) {
                eprintln!(
                    "failed to write criterion summary {}: {}",
                    path.display(),
                    err
                );
            }
        }
        if let Some(dir) = &self.estimates_output_dir {
            if let Err(err) = copy_estimate_reports(dir) {
                eprintln!(
                    "failed to copy criterion estimate reports to {}: {}",
                    dir.display(),
                    err
                );
            }
        }
        if self.clear_after {
            monitor().clear();
        }
    }
}

pub fn enter_context<N, U>(node_id: Option<N>, user_id: Option<U>) -> CriterionContextGuard
where
    N: Into<String>,
    U: Into<String>,
{
    CriterionContextGuard::new(node_id, user_id)
}

pub fn span<I, L>(labels: I) -> CriterionSpan
where
    I: IntoIterator<Item = L>,
    L: Into<String>,
{
    monitor().start_span(labels)
}

pub fn span_with_context<I, L, N, U>(
    node_id: Option<N>,
    user_id: Option<U>,
    labels: I,
) -> CriterionSpan
where
    I: IntoIterator<Item = L>,
    L: Into<String>,
    N: Into<String>,
    U: Into<String>,
{
    monitor().start_span_with_context(node_id, user_id, labels)
}

pub struct CriterionDisableGuard {
    previous: bool,
}

impl CriterionDisableGuard {
    fn new(previous: bool) -> Self {
        Self { previous }
    }
}

impl Drop for CriterionDisableGuard {
    fn drop(&mut self) {
        MONITOR_ENABLED.store(self.previous, AtomicOrdering::SeqCst);
    }
}

#[derive(Clone, Default)]
struct CriterionSummaryRow {
    node_id: String,
    user_id: String,
    module: String,
    operation: String,
    count: u64,
    total_duration_ns: u128,
    mean_ns: f64,
    median_ns: f64,
    std_dev_ns: f64,
}

struct CriterionSummary {
    rows: Vec<CriterionSummaryRow>,
    total_duration_ns: u128,
}

impl CriterionSummary {
    fn from_records(records: &[BenchmarkRecord]) -> Self {
        let mut totals: BTreeMap<(String, String, String, String), Vec<u128>> = BTreeMap::new();
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
            let entry = totals.entry(key).or_default();
            entry.push(record.duration_ns);
            total_duration_ns = total_duration_ns.saturating_add(record.duration_ns);
        }

        let mut rows = Vec::with_capacity(totals.len());
        for ((node_id, user_id, module, operation), durations) in totals.into_iter() {
            let mut row = CriterionSummaryRow {
                node_id,
                user_id,
                module,
                operation,
                count: durations.len() as u64,
                total_duration_ns: durations.iter().copied().sum(),
                mean_ns: 0.0,
                median_ns: 0.0,
                std_dev_ns: 0.0,
            };
            if !durations.is_empty() {
                let values: Vec<f64> = durations.iter().map(|d| *d as f64).collect();
                let sum: f64 = values.iter().sum();
                row.mean_ns = sum / values.len() as f64;
                let mut sorted = values.clone();
                sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                row.median_ns = if sorted.len() % 2 == 0 {
                    let mid = sorted.len() / 2;
                    (sorted[mid - 1] + sorted[mid]) / 2.0
                } else {
                    sorted[sorted.len() / 2]
                };
                if values.len() > 1 {
                    let mean = row.mean_ns;
                    let variance = values
                        .iter()
                        .map(|value| {
                            let diff = *value - mean;
                            diff * diff
                        })
                        .sum::<f64>()
                        / values.len() as f64;
                    row.std_dev_ns = variance.sqrt();
                } else {
                    row.std_dev_ns = 0.0;
                }
            }
            rows.push(row);
        }

        rows.sort_by(|a, b| b.total_duration_ns.cmp(&a.total_duration_ns));

        Self {
            rows,
            total_duration_ns,
        }
    }

    fn to_csv(&self) -> String {
        let mut out = String::from(
            "node_id,user_id,module,operation,count,total_ns,mean_ns,median_ns,std_dev_ns\n",
        );
        for row in &self.rows {
            out.push_str(&format!(
                "{},{},{},{},{},{},{:.3},{:.3},{:.3}\n",
                row.node_id,
                row.user_id,
                row.module,
                row.operation,
                row.count,
                row.total_duration_ns,
                row.mean_ns,
                row.median_ns,
                row.std_dev_ns,
            ));
        }
        out
    }

    fn to_json(&self) -> String {
        #[derive(serde::Serialize)]
        struct JsonRow<'a> {
            node_id: &'a str,
            user_id: &'a str,
            module: &'a str,
            operation: &'a str,
            count: u64,
            total_ns: u128,
            mean_ns: f64,
            median_ns: f64,
            std_dev_ns: f64,
        }

        #[derive(serde::Serialize)]
        struct JsonSummary<'a> {
            total_ns: u128,
            rows: Vec<JsonRow<'a>>,
        }

        let rows: Vec<JsonRow> = self
            .rows
            .iter()
            .map(|row| JsonRow {
                node_id: &row.node_id,
                user_id: &row.user_id,
                module: &row.module,
                operation: &row.operation,
                count: row.count,
                total_ns: row.total_duration_ns,
                mean_ns: row.mean_ns,
                median_ns: row.median_ns,
                std_dev_ns: row.std_dev_ns,
            })
            .collect();

        let summary = JsonSummary {
            total_ns: self.total_duration_ns,
            rows,
        };

        serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
    }

    fn module_breakdown(&self) -> Vec<(String, f64)> {
        let mut totals: BTreeMap<String, u128> = BTreeMap::new();
        for row in &self.rows {
            *totals.entry(row.module.clone()).or_insert(0) += row.total_duration_ns;
        }
        let total_duration = self.total_duration_ns.max(1) as f64;
        let mut breakdown: Vec<(String, f64)> = totals
            .into_iter()
            .map(|(module, duration)| (module, duration as f64 / total_duration))
            .collect();
        breakdown.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        breakdown
    }

    fn consensus_operation_stats(&self) -> Vec<ConsensusOperationStat> {
        let mut totals: BTreeMap<String, u128> = BTreeMap::new();
        for row in &self.rows {
            if row.module == "CONSENSUS" {
                *totals.entry(row.operation.clone()).or_insert(0) += row.total_duration_ns;
            }
        }

        let denominator = self.total_duration_ns.max(1) as f64;
        let mut stats: Vec<ConsensusOperationStat> = totals
            .into_iter()
            .map(|(operation, total_duration_ns)| ConsensusOperationStat {
                operation,
                total_duration_ns,
                share_of_total: total_duration_ns as f64 / denominator,
            })
            .collect();
        stats.sort_by(|a, b| b.total_duration_ns.cmp(&a.total_duration_ns));
        stats
    }
}

fn ensure_parent_directory(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn copy_estimate_reports(dest_root: &Path) -> io::Result<()> {
    let source_root = Path::new("target/criterion");
    if !source_root.exists() {
        return Ok(());
    }

    for group_entry in fs::read_dir(source_root)? {
        let group_entry = group_entry?;
        let group_path = group_entry.path();
        if !group_path.is_dir() {
            continue;
        }
        let Some(group_name) = group_path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        for func_entry in fs::read_dir(&group_path)? {
            let func_entry = func_entry?;
            let func_path = func_entry.path();
            if !func_path.is_dir() {
                continue;
            }

            let Some(func_name) = func_path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let source_estimates = func_path.join("new").join("estimates.json");
            if !source_estimates.exists() {
                continue;
            }

            let dest_dir = dest_root.join(group_name);
            fs::create_dir_all(&dest_dir)?;
            let dest_file = dest_dir.join(format!("{}.json", func_name));
            fs::copy(&source_estimates, &dest_file)?;
        }
    }

    Ok(())
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
                let _child = span.child(vec![String::from("sub")]);
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
        monitor().clear();
    }

    #[test]
    fn exports_summary_json() {
        monitor().clear();
        {
            let _ctx = enter_context(Some("node-a".to_string()), Some("user-a".to_string()));
            let _span = span(["task", "unit"]);
        }
        let json = monitor().export_summary_json();
        assert!(json.contains("\"total_ns\""));
        monitor().clear();
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
}
