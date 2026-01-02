#![cfg(feature = "handshake")]

use zk_gatekeeper::error::IdentityError;
use zk_gatekeeper::handshake::{
    initiator_finish, initiator_start, responder_accept, CapabilityFlags, NoiseStaticKeypair,
    RatchetState,
};
use zk_gatekeeper::identity::entropy::EntropySource;

struct DummyEntropy;
impl EntropySource for DummyEntropy {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError> {
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(31).wrapping_add(1);
        }
        Ok(())
    }
}

#[test]
fn handshake_roundtrip() {
    let mut entropy = DummyEntropy;
    let local = NoiseStaticKeypair::new(&mut entropy).unwrap();
    let remote = NoiseStaticKeypair::new(&mut entropy).unwrap();

    let (msg, state) = initiator_start(
        &local,
        &remote.public_key(),
        CapabilityFlags::VOICE,
        &mut entropy,
    )
    .unwrap();
    let (response, keys_responder) = responder_accept(
        &msg,
        &remote,
        &local.public_key(),
        CapabilityFlags::VOICE.union(CapabilityFlags::FILES),
        &mut entropy,
    )
    .unwrap();
    let keys_initiator = initiator_finish(state, &response, &local, &remote.public_key()).unwrap();

    assert_eq!(keys_initiator.shared_secret, keys_responder.shared_secret);
    assert_eq!(
        keys_initiator.negotiated_capabilities.bits(),
        CapabilityFlags::VOICE.bits()
    );

    let mut ratchet = RatchetState::new(keys_initiator.shared_secret);
    assert_ne!(ratchet.next_send_key(), [0u8; 32]);
    assert_ne!(ratchet.next_recv_key(), [0u8; 32]);
}
