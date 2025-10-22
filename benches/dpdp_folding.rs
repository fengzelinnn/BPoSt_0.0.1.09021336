use std::collections::HashMap;

use ark_bn254::Fr;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use num_bigint::BigUint;

use bpst::common::datastructures::{DPDPParams, DPDPProof, DPDPTags};
use bpst::crypto::dpdp::DPDP;
use bpst::crypto::folding::{dpdp_verification_relaxed_r1cs, RelaxedR1CS};
use bpst::monitoring::perf;

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
    let _guard = perf::monitor().scoped_disable();
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
    perf::monitor().clear();

    let mut group = c.benchmark_group("dPDP");
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
    for (label, share) in perf::monitor().consensus_pressure_report() {
        println!("  {label}: {share:.2}%");
    }
    perf::monitor().clear();
}

fn bench_folding(c: &mut Criterion) {
    let fixture = build_fixture(64, 1024, 16);
    perf::monitor().clear();

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

    println!("=== Folding consensus pressure ===");
    for (label, share) in perf::monitor().consensus_pressure_report() {
        println!("  {label}: {share:.2}%");
    }
    perf::monitor().clear();
}

criterion_group!(benches, bench_dpdp, bench_folding);
criterion_main!(benches);
