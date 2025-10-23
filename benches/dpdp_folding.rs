use std::collections::HashMap;
use std::time::Duration;

use ::criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ark_bn254::Fr;
use num_bigint::BigUint;

use bpst::common::datastructures::{DPDPParams, DPDPProof, DPDPTags};
use bpst::crypto::dpdp::DPDP;
use bpst::crypto::folding::{dpdp_verification_relaxed_r1cs, NovaFoldingCycle, RelaxedR1CS};
use bpst::monitoring::criterion;

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

fn bench_dpdp(c: &mut Criterion) {
    let fixture = build_fixture(64, 1024, 16);
    criterion::monitor().clear();

    let mut group = c.benchmark_group("dPDP");

    group.bench_function("key_gen", |b| {
        b.iter(|| {
            let params = DPDP::key_gen();
            black_box(params);
        });
    });

    let params = fixture.params.clone();
    let chunks = fixture.chunks.clone();
    group.bench_function("tag_file", |b| {
        b.iter(|| {
            let tags = DPDP::tag_file(black_box(&params), black_box(&chunks));
            black_box(tags);
        });
    });

    let tags_for_proof = fixture.tags.clone();
    let chunk_map = fixture.chunk_map.clone();
    let challenge = fixture.challenge.clone();
    let challenge_len = challenge.len();
    group.bench_function("gen_chal", |b| {
        b.iter(|| {
            let chal = DPDP::gen_chal(
                black_box("bench-fixture"),
                black_box(1),
                black_box(&tags_for_proof),
                Some(challenge_len),
            );
            black_box(chal);
        });
    });

    group.bench_function("gen_proof", |b| {
        b.iter(|| {
            let proof = DPDP::gen_proof(
                black_box(&tags_for_proof),
                black_box(&chunk_map),
                black_box(&challenge),
            );
            black_box(proof);
        });
    });

    let params_for_check = fixture.params.clone();
    let proof_for_check = fixture.proof.clone();
    group.bench_function("check_proof", |b| {
        b.iter(|| {
            let valid = DPDP::check_proof(
                black_box(&params_for_check),
                black_box(&proof_for_check),
                black_box(&challenge),
            );
            black_box(valid);
        });
    });

    group.finish();

    println!("=== dPDP consensus pressure ===");
    for (label, share) in criterion::monitor().consensus_pressure_report() {
        println!("  {label}: {share:.2}%");
    }
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
            let result = dpdp_verification_relaxed_r1cs(
                black_box(&params),
                black_box(&proof),
                black_box(&challenge),
            );
            black_box(result);
        });
    });

    let circuit = fixture.circuit.clone();
    group.bench_function("relaxed_is_satisfied", |b| {
        b.iter(|| {
            let satisfied = circuit.is_satisfied();
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
                let result = cycle.absorb_round(circuits).unwrap();
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
                let proof = cycle.finalize().unwrap().unwrap();
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
                let accumulator = NovaFoldingCycle::verify_final_accumulator(
                    proof.steps,
                    &proof.compressed_snark,
                    &proof.verifier_key,
                )
                .unwrap();
                black_box(accumulator);
            },
            BatchSize::SmallInput,
        );
    });

    nova_group.finish();

    println!("=== Folding consensus pressure ===");
    for (label, share) in criterion::monitor().consensus_pressure_report() {
        println!("  {label}: {share:.2}%");
    }
    criterion::monitor().clear();
}

criterion_group!(benches, bench_dpdp, bench_folding);
criterion_main!(benches);
