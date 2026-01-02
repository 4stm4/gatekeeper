use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zk_gatekeeper::contacts::poseidon_hash_pair;
use zk_gatekeeper::identity::hkdf::derive_user_key;
use zk_gatekeeper::identity::types::{DeviceId, IdentityState, RootKey};
use zk_gatekeeper::zk::prover::{DeterministicSchnorrProver, ZkProver};

fn bench_poseidon(c: &mut Criterion) {
    let left = [0u8; 32];
    let right = [1u8; 32];
    c.bench_function("poseidon_hash_pair", |b| {
        b.iter(|| {
            black_box(poseidon_hash_pair(black_box(&left), black_box(&right)));
        })
    });
}

fn bench_hkdf(c: &mut Criterion) {
    let root = RootKey([0x55; 32]);
    let device = DeviceId([0x11; 16]);
    c.bench_function("derive_user_key", |b| {
        b.iter(|| {
            let _ = black_box(derive_user_key(&root, &device).unwrap());
        })
    });
}

fn bench_prover(c: &mut Criterion) {
    let state = IdentityState::from_root(RootKey([0x23; 32]), DeviceId([0x33; 16])).unwrap();
    let challenge = b"bench-challenge";
    let prover = DeterministicSchnorrProver::default();
    c.bench_function("deterministic_prove", |b| {
        b.iter(|| {
            let proof = state.prove_with(&prover, challenge).unwrap();
            black_box(proof);
        })
    });
}

criterion_group!(benches, bench_poseidon, bench_hkdf, bench_prover);
criterion_main!(benches);
