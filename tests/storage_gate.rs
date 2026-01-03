#![cfg(feature = "storage-gate")]

use zk_gatekeeper::identity::types::{DeviceId, IdentityState, RootKey};
use zk_gatekeeper::storage::gate::{
    BlobAccessEntry, BlobAccessGate, BlobFetchChallenge, BlobIdentityProver, BLOB_PROOF_DOMAIN,
};

fn state() -> IdentityState {
    let root = RootKey::from_bytes([7u8; 32]);
    let device = DeviceId([2u8; 16]);
    IdentityState::from_root(root, device).unwrap()
}

#[test]
fn blob_gate_roundtrip() {
    let identity = state();
    let challenge = BlobFetchChallenge {
        blob_id: [0xAA; 32],
        nonce: [0x55; 32],
    };
    let prover = BlobIdentityProver::new(&identity);
    let request = prover.prove(&challenge).unwrap();

    let mut gate = BlobAccessGate::new(BLOB_PROOF_DOMAIN);
    gate.register(BlobAccessEntry {
        blob_id: challenge.blob_id,
        identity: identity.identifier(),
        public_key: identity.public_key().into_bytes(),
    });

    let grant = gate.verify(&challenge, &request).unwrap();
    assert_eq!(grant.blob_id, challenge.blob_id);
}
