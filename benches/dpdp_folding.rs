use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use ::criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ark_bn254::Fr;
use num_bigint::BigUint;

use bpst::common::datastructures::{DPDPParams, DPDPProof, DPDPTags};
use bpst::crypto::dpdp::DPDP;
use bpst::crypto::folding::{dpdp_verification_relaxed_r1cs, NovaFoldingCycle, RelaxedR1CS};
use bpst::monitoring::criterion;

const CONSENSUS_OPERATIONS: &[&str; 4] = [
    "mining",
    "fork_handling",
    "block_production",
    "threshold_judgement",
];

#[derive(Clone)]
struct BenchmarkFixture {
    params: DPDPParams,
    chunks: Vec<Vec<u8>>,
    tags: DPDPTags,
    chunk_map: HashMap<usize, Vec<u8>>,
    challenge: Vec<(usize, BigUint)>,
    proof: DPDPProof,
    circuit: RelaxedR1CS<Fr>,
}

fn sample_chunks(count: usize, size: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let mut chunk = vec![0u8; size];
            for (idx, byte) in chunk.iter_mut().enumerate() {
                *byte = ((i + idx) % 251) as u8;
            }
            chunk
        })
        .collect()
}

fn build_fixture(
    chunk_count: usize,
    chunk_size: usize,
    challenge_count: usize,
) -> BenchmarkFixture {
    let _guard = criterion::monitor().scoped_disable();
    let params = DPDP::key_gen();
    let chunks = sample_chunks(chunk_count, chunk_size);
    let tags = DPDP::tag_file(&params, &chunks);
    let challenge = DPDP::gen_chal("bench-fixture", 1, &tags, Some(challenge_count));
    let chunk_map = chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| (i, chunk.clone()))
        .collect::<HashMap<_, _>>();
    let proof = DPDP::gen_proof(&tags, &chunk_map, &challenge);
    let (circuit, _) = dpdp_verification_relaxed_r1cs(&params, &proof, &challenge);
    BenchmarkFixture {
        params,
        chunks,
        tags,
        chunk_map,
        challenge,
        proof,
        circuit,
    }
}

fn format_duration(ns: u128) -> String {
    let seconds = ns as f64 / 1_000_000_000.0;
    if seconds >= 1.0 {
        format!("{seconds:.3}s")
    } else {
        let millis = ns as f64 / 1_000_000.0;
        if millis >= 1.0 {
            format!("{millis:.3}ms")
        } else {
            let micros = ns as f64 / 1_000.0;
            format!("{micros:.3}µs")
        }
    }
}

fn print_runtime_report(label: &str) {
    let total_ns = criterion::monitor().total_duration_ns();
    println!("=== {label} total runtime ===");
    println!("  total: {} ({} ns)", format_duration(total_ns), total_ns);

    let stats = criterion::monitor().consensus_operation_stats();
    let consensus_total_ns: u128 = stats.iter().map(|entry| entry.total_duration_ns).sum();
    let total_denominator = if total_ns == 0 { 1.0 } else { total_ns as f64 };

    println!("=== {label} consensus operations ===");
    println!(
        "  total: {} ({} ns, {:.2}% of overall)",
        format_duration(consensus_total_ns),
        consensus_total_ns,
        (consensus_total_ns as f64 / total_denominator) * 100.0
    );

    for &operation in CONSENSUS_OPERATIONS {
        if let Some(stat) = stats.iter().find(|entry| entry.operation == operation) {
            println!(
                "  {operation}: {} ({} ns, {:.2}% of overall)",
                format_duration(stat.total_duration_ns),
                stat.total_duration_ns,
                stat.share_of_total * 100.0
            );
        } else {
            println!(
                "  {operation}: {} (0 ns, 0.00% of overall)",
                format_duration(0)
            );
        }
    }

    let mut other_operations: Vec<_> = stats
        .iter()
        .filter(|entry| {
            !CONSENSUS_OPERATIONS
                .iter()
                .any(|name| *name == entry.operation)
        })
        .collect();
    if !other_operations.is_empty() {
        other_operations.sort_by(|a, b| b.total_duration_ns.cmp(&a.total_duration_ns));
        println!("  other consensus operations:");
        for entry in other_operations {
            println!(
                "    {}: {} ({} ns, {:.2}% of overall)",
                entry.operation,
                format_duration(entry.total_duration_ns),
                entry.total_duration_ns,
                entry.share_of_total * 100.0
            );
        }
    }
}

fn copy_function_estimates_to_category_level() {
    if let Err(err) = copy_function_estimates_to_category_level_inner() {
        eprintln!(
            "failed to copy criterion function estimates to category level: {}",
            err
        );
    }
}

fn copy_function_estimates_to_category_level_inner() -> io::Result<()> {
    let source_root = Path::new("target/criterion");
    if !source_root.exists() {
        return Ok(());
    }

    for category_entry in fs::read_dir(source_root)? {
        let category_entry = category_entry?;
        let category_path = category_entry.path();
        if !category_path.is_dir() {
            continue;
        }
        copy_category_new_estimate(&category_path)?;
        copy_estimates_for_category(&category_path, &category_path)?;
    }

    Ok(())
}

fn copy_category_new_estimate(category_path: &Path) -> io::Result<()> {
    let Some(category_name) = category_path.file_name().and_then(|n| n.to_str()) else {
        return Ok(());
    };
    if !matches!(category_name, "Folding" | "Nova") {
        return Ok(());
    }

    let source_estimates = category_path.join("new").join("estimates.json");
    if source_estimates.exists() {
        let destination = category_path.join("new.json");
        fs::copy(source_estimates, destination)?;
    }

    Ok(())
}

fn copy_estimates_for_category(path: &Path, category_root: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child_path = entry.path();
        if !child_path.is_dir() {
            continue;
        }

        let Some(name) = child_path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if !matches!(name, "new" | "old") {
            copy_category_new_estimate(&child_path)?;
        }

        if child_path != category_root {
            if matches!(name, "new" | "old") {
                continue;
            }

            let source_estimates = child_path.join("new").join("estimates.json");
            if source_estimates.exists() {
                let destination = category_root.join(format!("{name}.json"));
                fs::copy(&source_estimates, &destination)?;
            }
        }

        if !matches!(name, "new" | "old") {
            copy_estimates_for_category(&child_path, category_root)?;
        }
    }

    Ok(())
}

fn bench_dpdp(c: &mut Criterion) {
    let fixture = build_fixture(64, 1024, 16);
    criterion::monitor().clear();

    let mut group = c.benchmark_group("dPDP");

    group.bench_function("key_gen", |b| {
        b.iter(|| {
            let params = record_single_step(["bench", "dPDP", "key_gen"], || DPDP::key_gen());
            black_box(params);
        });
    });

    let params = fixture.params.clone();
    let chunks = fixture.chunks.clone();
    group.bench_function("tag_file", |b| {
        b.iter(|| {
            let tags = record_single_step(["bench", "dPDP", "tag_file"], || {
                DPDP::tag_file(black_box(&params), black_box(&chunks))
            });
            black_box(tags);
        });
    });

    let tags_for_proof = fixture.tags.clone();
    let chunk_map = fixture.chunk_map.clone();
    let challenge = fixture.challenge.clone();
    let challenge_len = challenge.len();
    group.bench_function("gen_chal", |b| {
        b.iter(|| {
            let chal = record_single_step(["bench", "dPDP", "gen_chal"], || {
                DPDP::gen_chal(
                    black_box("bench-fixture"),
                    black_box(1),
                    black_box(&tags_for_proof),
                    Some(challenge_len),
                )
            });
            black_box(chal);
        });
    });

    group.bench_function("gen_proof", |b| {
        b.iter(|| {
            let proof = record_single_step(["bench", "dPDP", "gen_proof"], || {
                DPDP::gen_proof(
                    black_box(&tags_for_proof),
                    black_box(&chunk_map),
                    black_box(&challenge),
                )
            });
            black_box(proof);
        });
    });

    let params_for_check = fixture.params.clone();
    let proof_for_check = fixture.proof.clone();
    group.bench_function("check_proof", |b| {
        b.iter(|| {
            let valid = record_single_step(["bench", "dPDP", "check_proof"], || {
                DPDP::check_proof(
                    black_box(&params_for_check),
                    black_box(&proof_for_check),
                    black_box(&challenge),
                )
            });
            black_box(valid);
        });
    });

    group.finish();

    print_runtime_report("dPDP");

    println!("=== dPDP consensus pressure ===");
    for (label, share) in criterion::monitor().consensus_pressure_report() {
        println!("  {label}: {share:.2}%");
    }
    copy_function_estimates_to_category_level();
    criterion::monitor().clear();
}

fn bench_folding(c: &mut Criterion) {
    let fixture = build_fixture(64, 1024, 16);
    criterion::monitor().clear();

    let mut group = c.benchmark_group("Folding");
    let params = fixture.params.clone();
    let proof = fixture.proof.clone();
    let challenge = fixture.challenge.clone();
    group.bench_function("dpdp_relaxed_r1cs", |b| {
        b.iter(|| {
            let result = record_single_step(["bench", "Folding", "dpdp_relaxed_r1cs"], || {
                dpdp_verification_relaxed_r1cs(
                    black_box(&params),
                    black_box(&proof),
                    black_box(&challenge),
                )
            });
            black_box(result);
        });
    });

    let circuit = fixture.circuit.clone();
    group.bench_function("relaxed_is_satisfied", |b| {
        b.iter(|| {
            let satisfied =
                record_single_step(["bench", "Folding", "relaxed_is_satisfied"], || {
                    circuit.is_satisfied()
                });
            black_box(satisfied);
        });
    });

    group.finish();

    let mut nova_group = c.benchmark_group("Folding/Nova");
    nova_group.sample_size(10);
    nova_group.warm_up_time(Duration::from_secs(1));
    nova_group.measurement_time(Duration::from_secs(45));

    let base_circuit = fixture.circuit.clone();
    nova_group.bench_function("nova_absorb_round", |b| {
        let base_circuit = base_circuit.clone();
        b.iter_batched(
            move || {
                let cycle = NovaFoldingCycle::new(1);
                let circuits = vec![base_circuit.clone()];
                (cycle, circuits)
            },
            |(mut cycle, circuits)| {
                let result =
                    record_single_step(["bench", "Folding", "Nova", "absorb_round"], || {
                        cycle.absorb_round(circuits).unwrap()
                    });
                black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    let base_circuit = fixture.circuit.clone();
    nova_group.bench_function("nova_finalize", |b| {
        let base_circuit = base_circuit.clone();
        b.iter_batched(
            move || {
                let mut cycle = NovaFoldingCycle::new(2);
                for _ in 0..2 {
                    let circuits = vec![base_circuit.clone()];
                    cycle.absorb_round(circuits).unwrap();
                }
                cycle
            },
            |mut cycle| {
                let proof = record_single_step(["bench", "Folding", "Nova", "finalize"], || {
                    cycle.finalize().unwrap().unwrap()
                });
                black_box(proof);
            },
            BatchSize::SmallInput,
        );
    });

    let base_circuit = fixture.circuit.clone();
    nova_group.bench_function("nova_verify_final", |b| {
        let base_circuit = base_circuit.clone();
        b.iter_batched(
            move || {
                let mut cycle = NovaFoldingCycle::new(2);
                for _ in 0..2 {
                    let circuits = vec![base_circuit.clone()];
                    cycle.absorb_round(circuits).unwrap();
                }
                cycle.finalize().unwrap().unwrap()
            },
            |proof| {
                let accumulator =
                    record_single_step(["bench", "Folding", "Nova", "verify_final"], || {
                        NovaFoldingCycle::verify_final_accumulator(
                            proof.steps,
                            &proof.compressed_snark,
                            &proof.verifier_key,
                        )
                        .unwrap()
                    });
                black_box(accumulator);
            },
            BatchSize::SmallInput,
        );
    });

    nova_group.finish();

    print_runtime_report("Folding");

    println!("=== Folding consensus pressure ===");
    for (label, share) in criterion::monitor().consensus_pressure_report() {
        println!("  {label}: {share:.2}%");
    }
    copy_function_estimates_to_category_level();
    copy_new_estimates_for_category("Folding");
    copy_new_estimates_for_category("Folding/Nova");
    criterion::monitor().clear();
}

criterion_group!(benches, bench_dpdp, bench_folding);
criterion_main!(benches);

fn record_single_step<F, R, const N: usize>(labels: [&str; N], f: F) -> R
where
    F: FnOnce() -> R,
{
    let span = criterion::span(labels.into_iter());
    let result = f();
    drop(span);
    result
}

fn copy_new_estimates_for_category(category: &str) {
    if let Err(err) = copy_new_estimates_for_category_inner(category) {
        eprintln!(
            "failed to copy criterion new estimates for {category}: {}",
            err
        );
    }
}

fn copy_new_estimates_for_category_inner(category: &str) -> io::Result<()> {
    let mut category_path = Path::new("target/criterion").to_path_buf();
    for part in category.split('/') {
        category_path.push(part);
    }

    let source = category_path.join("new").join("estimates.json");
    if source.exists() {
        let destination = category_path.join("new.json");
        fs::copy(source, destination)?;
    }

    Ok(())
}
