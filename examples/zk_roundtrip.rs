//! Проверка связки prover ↔ verifier на хосте.
use zk_gatekeeper::identity::entropy::DummyEntropy;
use zk_gatekeeper::identity::init::init_identity;
use zk_gatekeeper::identity::types::DeviceId;
use zk_gatekeeper::zk::prover::DeterministicSchnorrProver;
use zk_gatekeeper::zk::verifier::{ChallengeTrackerConfig, Verifier};

fn main() {
    let mut entropy = DummyEntropy;
    let device = DeviceId([0x55; 16]);
    let identity = init_identity(&mut entropy, device).expect("identity init failed");

    let prover = DeterministicSchnorrProver::default();
    let challenge = b"host-roundtrip";
    let proof = identity
        .prove_with(&prover, challenge)
        .expect("prove failed");

    let config = ChallengeTrackerConfig::new(8, 10);
    let mut verifier = Verifier::new(b"zk-gatekeeper-schnorr-v1", config);
    let now = 1u64;
    verifier
        .tracker_mut()
        .register(challenge, now)
        .expect("register failed");

    let pk = identity.public_key();
    verifier
        .verify(
            &identity.identifier(),
            pk.as_bytes(),
            challenge,
            now,
            &proof,
        )
        .expect("verification failed");

    println!(
        "verification succeeded for identity {:x?}",
        identity.identifier().as_bytes()
    );
}
