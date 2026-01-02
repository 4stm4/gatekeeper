use zk_gatekeeper::identity::access::IdentityState;
use zk_gatekeeper::identity::init::recover_identity_from_seed;
use zk_gatekeeper::identity::seed::SeedPhrase;
use zk_gatekeeper::identity::types::{DeviceId, RootKey};

fn sample_state() -> IdentityState {
    let root = RootKey([7u8; 32]);
    let device = DeviceId([1u8; 16]);
    IdentityState::from_root(root, device).unwrap()
}

#[test]
fn public_key_and_identifier_match() {
    let state = sample_state();
    let pk = state.public_key().into_bytes();
    let id = state.identifier();
    assert!(id.matches(&pk));
}

#[test]
fn seed_phrase_roundtrip() {
    let state = sample_state();
    let seed = SeedPhrase::from_root(&state.root_key);
    let words = seed.words();
    let phrase = SeedPhrase::from_slice(&words).unwrap();
    let recovered = recover_identity_from_seed(&phrase, state.device_id()).unwrap();
    assert!(recovered
        .identifier()
        .matches(state.public_key().as_bytes()));
}
