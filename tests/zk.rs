use zk_gatekeeper::identity::types::{DeviceId, IdentityState, RootKey};
use zk_gatekeeper::zk::prover::DeterministicSchnorrProver;
use zk_gatekeeper::zk::verifier::{ChallengeTracker, ChallengeTrackerConfig, Verifier};

fn make_state() -> IdentityState {
    let root = RootKey::from_bytes([42u8; 32]);
    let device = DeviceId([1u8; 16]);
    IdentityState::from_root(root, device).unwrap()
}

#[test]
fn prover_verifier_roundtrip() {
    let state = make_state();
    let challenge = b"1234567890abcdef";
    let prover = DeterministicSchnorrProver::default();
    let proof = state.prove_with(&prover, challenge).unwrap();

    let config = ChallengeTrackerConfig::new(8, 10);
    let mut verifier = Verifier::new(b"zk-gatekeeper-schnorr-v1", config);
    verifier.tracker_mut().register(challenge, 1).unwrap();

    let pk = state.public_key().into_bytes();
    let id = state.identifier();

    verifier.verify(&id, &pk, challenge, 2, &proof).unwrap();
}

#[test]
fn replay_detected() {
    let state = make_state();
    let challenge = b"xyz987";
    let prover = DeterministicSchnorrProver::default();
    let proof = state.prove_with(&prover, challenge).unwrap();

    let config = ChallengeTrackerConfig::new(4, 5);
    let mut verifier = Verifier::new(b"zk-gatekeeper-schnorr-v1", config);
    verifier.tracker_mut().register(challenge, 10).unwrap();
    let pk = state.public_key().into_bytes();
    let id = state.identifier();

    verifier.verify(&id, &pk, challenge, 11, &proof).unwrap();
    assert!(verifier.verify(&id, &pk, challenge, 12, &proof).is_err());
}

#[test]
fn tracker_ttl_and_lru() {
    let mut tracker = ChallengeTracker::new(ChallengeTrackerConfig::new(2, 5));
    tracker.register(b"one", 1).unwrap();
    tracker.register(b"two", 2).unwrap();
    // registering third entry should evict "one"
    tracker.register(b"three", 3).unwrap();
    assert!(tracker.consume(b"one", 3).is_err());
    // advance time to expire "two"
    assert!(tracker.consume(b"two", 10).is_err());
    tracker.register(b"four", 11).unwrap();
    assert!(tracker.consume(b"four", 12).is_ok());
}
