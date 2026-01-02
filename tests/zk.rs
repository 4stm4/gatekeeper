use zk_gatekeeper::identity::types::{DeviceId, IdentityState, RootKey};
use zk_gatekeeper::zk::prover::{DeterministicSchnorrProver, ZkProver};
use zk_gatekeeper::zk::verifier::Verifier;

fn make_state() -> IdentityState {
    let root = RootKey([42u8; 32]);
    let device = DeviceId([1u8; 16]);
    IdentityState::from_root(root, device).unwrap()
}

#[test]
fn prover_verifier_roundtrip() {
    let state = make_state();
    let challenge = b"1234567890abcdef";
    let prover = DeterministicSchnorrProver::default();
    let proof = state.prove_with(&prover, challenge).unwrap();

    let mut verifier = Verifier::<8>::new(b"zk-gatekeeper-schnorr-v1");
    verifier.tracker_mut().register(challenge).unwrap();

    let pk = state.public_key().into_bytes();
    let id = state.identifier();

    verifier.verify(&id, &pk, challenge, &proof).unwrap();
}

#[test]
fn replay_detected() {
    let state = make_state();
    let challenge = b"xyz987";
    let prover = DeterministicSchnorrProver::default();
    let proof = state.prove_with(&prover, challenge).unwrap();

    let mut verifier = Verifier::<4>::new(b"zk-gatekeeper-schnorr-v1");
    verifier.tracker_mut().register(challenge).unwrap();
    let pk = state.public_key().into_bytes();
    let id = state.identifier();

    verifier.verify(&id, &pk, challenge, &proof).unwrap();
    assert!(verifier.verify(&id, &pk, challenge, &proof).is_err());
}
