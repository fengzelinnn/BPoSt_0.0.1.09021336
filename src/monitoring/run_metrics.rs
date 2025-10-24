use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use sysinfo::{get_current_pid, System};

#[derive(Clone, Default)]
struct RunMetric {
    timestamp: chrono::DateTime<Utc>,
    category: String,
    metric: String,
    value: f64,
    raw_value: String,
    unit: String,
    extra: BTreeMap<String, String>,
}

impl RunMetric {
    fn to_csv_row(&self) -> String {
        let timestamp = self.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);
        let extra_json = serde_json::to_string(&self.extra).unwrap_or_else(|_| "{}".into());
        format!(
            "{},{},{},{:.6},{},{},{}\n",
            timestamp,
            self.category,
            self.metric,
            self.value,
            self.raw_value,
            self.unit,
            extra_json
        )
    }
}

#[derive(Default)]
pub struct RunMetricsCollector {
    metrics: Mutex<Vec<RunMetric>>,
}

static RUN_METRICS: Lazy<RunMetricsCollector> = Lazy::new(RunMetricsCollector::default);

pub fn metrics() -> &'static RunMetricsCollector {
    &RUN_METRICS
}

impl RunMetricsCollector {
    fn record(&self, metric: RunMetric) {
        self.metrics.lock().push(metric);
    }

    fn record_numeric_metric<S1, S2, S3>(
        &self,
        category: S1,
        metric: S2,
        value: f64,
        raw_value: String,
        unit: S3,
        extra: BTreeMap<String, String>,
    ) where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        self.record(RunMetric {
            timestamp: Utc::now(),
            category: category.into(),
            metric: metric.into(),
            value,
            raw_value,
            unit: unit.into(),
            extra,
        });
    }

    pub fn record_block_size(&self, node_id: &str, height: u64, size_bytes: usize) {
        let mut extra = BTreeMap::new();
        extra.insert("node_id".into(), node_id.to_string());
        extra.insert("height".into(), height.to_string());
        self.record_numeric_metric(
            "consensus",
            "block_size_bytes",
            size_bytes as f64,
            size_bytes.to_string(),
            "B",
            extra,
        );
    }

    pub fn record_folding_round_time(
        &self,
        node_id: &str,
        file_id: &str,
        block_height: u64,
        round: usize,
        circuit_count: usize,
        duration_ns: u128,
    ) {
        let mut extra = BTreeMap::new();
        extra.insert("node_id".into(), node_id.to_string());
        extra.insert("file_id".into(), file_id.to_string());
        extra.insert("block_height".into(), block_height.to_string());
        extra.insert("round".into(), round.to_string());
        extra.insert("circuit_count".into(), circuit_count.to_string());
        self.record_numeric_metric(
            "folding",
            "round_duration_ns",
            duration_ns as f64,
            duration_ns.to_string(),
            "ns",
            extra,
        );
    }

    pub fn record_folding_proof_size(
        &self,
        node_id: &str,
        file_id: &str,
        block_height: u64,
        round: usize,
        proof_bytes: usize,
    ) {
        let mut extra = BTreeMap::new();
        extra.insert("node_id".into(), node_id.to_string());
        extra.insert("file_id".into(), file_id.to_string());
        extra.insert("block_height".into(), block_height.to_string());
        extra.insert("round".into(), round.to_string());
        self.record_numeric_metric(
            "folding",
            "round_proof_size_bytes",
            proof_bytes as f64,
            proof_bytes.to_string(),
            "B",
            extra,
        );
    }

    pub fn record_dpdp_proof_latency(
        &self,
        node_id: &str,
        file_id: &str,
        challenge_len: usize,
        duration_ns: u128,
    ) {
        let mut extra = BTreeMap::new();
        extra.insert("node_id".into(), node_id.to_string());
        extra.insert("file_id".into(), file_id.to_string());
        extra.insert("challenge_len".into(), challenge_len.to_string());
        self.record_numeric_metric(
            "dpdp",
            "proof_latency_ns",
            duration_ns as f64,
            duration_ns.to_string(),
            "ns",
            extra,
        );
    }

    pub fn record_dpdp_proof_size(
        &self,
        node_id: &str,
        file_id: &str,
        block_height: Option<u64>,
        round: Option<usize>,
        proof_bytes: usize,
    ) {
        let mut extra = BTreeMap::new();
        extra.insert("node_id".into(), node_id.to_string());
        extra.insert("file_id".into(), file_id.to_string());
        if let Some(height) = block_height {
            extra.insert("block_height".into(), height.to_string());
        }
        if let Some(round) = round {
            extra.insert("round".into(), round.to_string());
        }
        self.record_numeric_metric(
            "dpdp",
            "proof_size_bytes",
            proof_bytes as f64,
            proof_bytes.to_string(),
            "B",
            extra,
        );
    }

    pub fn record_dpdp_tag_throughput(
        &self,
        owner_id: &str,
        file_id: &str,
        total_bytes: usize,
        duration_ns: u128,
    ) {
        let mut extra = BTreeMap::new();
        extra.insert("owner_id".into(), owner_id.to_string());
        extra.insert("file_id".into(), file_id.to_string());
        extra.insert("total_bytes".into(), total_bytes.to_string());
        extra.insert("duration_ns".into(), duration_ns.to_string());
        let duration_secs = (duration_ns as f64) / 1_000_000_000.0;
        let throughput = if duration_secs > f64::EPSILON {
            total_bytes as f64 / duration_secs
        } else {
            total_bytes as f64
        };
        self.record_numeric_metric(
            "dpdp",
            "tag_throughput_Bps",
            throughput,
            format!("{throughput:.3}"),
            "B/s",
            extra,
        );
    }

    pub fn record_final_folding_proof_artifact(
        &self,
        file_id: &str,
        steps: usize,
        proof_bytes: usize,
        vk_bytes: usize,
        prove_ns: u128,
    ) {
        let mut common = BTreeMap::new();
        common.insert("file_id".into(), file_id.to_string());
        common.insert("steps".into(), steps.to_string());
        self.record_numeric_metric(
            "folding",
            "final_proof_size_bytes",
            proof_bytes as f64,
            proof_bytes.to_string(),
            "B",
            common.clone(),
        );
        self.record_numeric_metric(
            "folding",
            "final_verifier_key_size_bytes",
            vk_bytes as f64,
            vk_bytes.to_string(),
            "B",
            common.clone(),
        );
        self.record_numeric_metric(
            "folding",
            "final_prove_latency_ns",
            prove_ns as f64,
            prove_ns.to_string(),
            "ns",
            common.clone(),
        );
    }

    pub fn record_final_folding_verify_latency(
        &self,
        file_id: &str,
        steps: usize,
        verify_ns: u128,
    ) {
        let mut extra = BTreeMap::new();
        extra.insert("file_id".into(), file_id.to_string());
        extra.insert("steps".into(), steps.to_string());
        self.record_numeric_metric(
            "folding",
            "final_verify_latency_ns",
            verify_ns as f64,
            verify_ns.to_string(),
            "ns",
            extra,
        );
    }

    pub fn record_cpu_snapshot(&self) {
        let mut system = System::new_all();
        system.refresh_cpu();
        system.refresh_memory();
        let pid = get_current_pid().ok();
        if let Some(pid) = pid {
            system.refresh_process(pid);
        }
        thread::sleep(Duration::from_millis(200));
        system.refresh_cpu();
        system.refresh_memory();
        if let Some(pid) = pid {
            system.refresh_process(pid);
        }

        let cpu = system.global_cpu_info().cpu_usage();
        let total_memory = system.total_memory() * 1024;
        let used_memory = system.used_memory() * 1024;
        let mut system_extra = BTreeMap::new();
        system_extra.insert("scope".into(), "system".into());
        system_extra.insert("total_memory_bytes".into(), total_memory.to_string());
        system_extra.insert("used_memory_bytes".into(), used_memory.to_string());
        self.record_numeric_metric(
            "system",
            "cpu_usage_percent",
            cpu as f64,
            format!("{cpu:.3}"),
            "%",
            system_extra,
        );

        if let Some(pid) = pid {
            if let Some(process) = system.process(pid) {
                let mut cpu_extra = BTreeMap::new();
                cpu_extra.insert("pid".into(), pid.as_u32().to_string());
                self.record_numeric_metric(
                    "process",
                    "cpu_usage_percent",
                    process.cpu_usage() as f64,
                    format!("{:.3}", process.cpu_usage()),
                    "%",
                    cpu_extra.clone(),
                );

                let mut mem_extra = BTreeMap::new();
                mem_extra.insert("pid".into(), pid.as_u32().to_string());
                self.record_numeric_metric(
                    "process",
                    "memory_usage_bytes",
                    (process.memory() * 1024) as f64,
                    (process.memory() * 1024).to_string(),
                    "B",
                    mem_extra,
                );
            }
        }
    }

    pub fn export_csv(&self) -> String {
        let mut out = String::from("timestamp,category,metric,value,value_raw,unit,extra\n");
        for metric in self.metrics.lock().iter() {
            out.push_str(&metric.to_csv_row());
        }
        out
    }

    pub fn write_csv_to<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, self.export_csv())
    }
}

pub struct RunMetricsExportGuard {
    csv_path: Option<PathBuf>,
    record_cpu: bool,
}

impl RunMetricsExportGuard {
    pub fn from_env() -> Self {
        let csv_path = match std::env::var("BPST_RUN_METRICS_CSV") {
            Ok(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty()
                    || trimmed == "0"
                    || trimmed.eq_ignore_ascii_case("false")
                    || trimmed.eq_ignore_ascii_case("off")
                {
                    None
                } else {
                    Some(PathBuf::from(trimmed.to_owned()))
                }
            }
            Err(_) => Some(PathBuf::from("target/run_metrics.csv")),
        };

        let record_cpu = std::env::var("BPST_RUN_METRICS_CPU")
            .map(|value| !(value == "0" || value.eq_ignore_ascii_case("false")))
            .unwrap_or(true);
        Self {
            csv_path,
            record_cpu,
        }
    }

    pub fn new(csv_path: Option<PathBuf>, record_cpu: bool) -> Self {
        Self {
            csv_path,
            record_cpu,
        }
    }
}

impl Drop for RunMetricsExportGuard {
    fn drop(&mut self) {
        if self.record_cpu {
            metrics().record_cpu_snapshot();
        }
        if let Some(path) = &self.csv_path {
            if let Err(err) = metrics().write_csv_to(path) {
                eprintln!(
                    "failed to write run metrics CSV {}: {}",
                    path.display(),
                    err
                );
            }
        }
    }
}
