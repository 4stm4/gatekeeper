use core::cell::Cell;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use stacker::{maybe_grow, remaining_stack};
use zk_gatekeeper::identity::entropy::MockEntropy;
use zk_gatekeeper::identity::init::init_identity;
use zk_gatekeeper::identity::types::DeviceId;
use zk_gatekeeper::zk::prover::{DeterministicSchnorrProver, ZkProver};

static ENTROPY_INIT: [u8; 64] = [0xA5; 64];
static ENTROPY_PROVE: [u8; 64] = [0x5A; 64];
static CHALLENGE: [u8; 32] = *b"criterion-stack-challenge-000000";

fn bench_init_identity(c: &mut Criterion) {
    let max_stack = Cell::new(0usize);
    c.bench_function("identity_init_stack", |b| {
        b.iter(|| {
            let used = measure_stack_usage(|| {
                let mut entropy = MockEntropy::from_slice(&ENTROPY_INIT);
                let device = DeviceId([0x11; 16]);
                black_box(init_identity(&mut entropy, device).unwrap());
            });
            max_stack.set(max_stack.get().max(used));
            black_box(used);
        });
    });
    println!("identity_init_stack: peak {} bytes", max_stack.get());
}

fn bench_zk_prove(c: &mut Criterion) {
    let mut entropy = MockEntropy::from_slice(&ENTROPY_PROVE);
    let state = Box::leak(Box::new(
        init_identity(&mut entropy, DeviceId([0x22; 16])).expect("identity init failed"),
    ));
    let prover = DeterministicSchnorrProver::default();
    let max_stack = Cell::new(0usize);

    c.bench_function("zk_prove_stack", |b| {
        b.iter(|| {
            let used = measure_stack_usage(|| {
                let proof = state.prove_with(&prover, &CHALLENGE).unwrap();
                black_box(proof);
            });
            max_stack.set(max_stack.get().max(used));
            black_box(used);
        });
    });
    println!("zk_prove_stack: peak {} bytes", max_stack.get());
}

fn measure_stack_usage<F: FnOnce()>(f: F) -> usize {
    maybe_grow(32 * 1024, 128 * 1024, || {
        let before = remaining_stack();
        f();
        let after = remaining_stack();
        match (before, after) {
            (Some(b), Some(a)) => b.saturating_sub(a),
            _ => 0,
        }
    })
}

fn stack_suite(c: &mut Criterion) {
    bench_init_identity(c);
    bench_zk_prove(c);
}

criterion_group!(stack_profile, stack_suite);
criterion_main!(stack_profile);
