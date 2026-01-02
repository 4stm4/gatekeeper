use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::IdentityError;
use crate::handshake::capability::{CapabilityFlags, CapabilityManager};
use crate::identity::entropy::EntropySource;

type HmacSha256 = Hmac<Sha256>;

const HANDSHAKE_VERSION: u8 = 1;
const LABEL_INITIAL: &[u8] = b"gatekeeper-noise-init";
const LABEL_FINAL: &[u8] = b"gatekeeper-noise-final";
const LABEL_MAC: &[u8] = b"gatekeeper-noise-mac";

#[derive(Clone)]
pub struct NoiseStaticKeypair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl NoiseStaticKeypair {
    pub fn new<E: EntropySource>(entropy: &mut E) -> Result<Self, IdentityError> {
        let mut buf = [0u8; 32];
        entropy.fill_bytes(&mut buf)?;
        Ok(Self::from_secret(buf))
    }

    pub fn from_secret(secret: [u8; 32]) -> Self {
        let scalar = StaticSecret::from(secret);
        let public = PublicKey::from(&scalar).to_bytes();
        Self { secret, public }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

#[derive(Clone, Copy)]
pub struct HandshakeMessage {
    pub version: u8,
    pub capabilities: CapabilityFlags,
    pub ephemeral: [u8; 32],
    pub mac: [u8; 32],
}

pub struct HandshakeKeys {
    pub shared_secret: [u8; 32],
    pub negotiated_capabilities: CapabilityFlags,
}

pub struct InitiatorState {
    ck: [u8; 32],
    ephemeral_secret: [u8; 32],
    capabilities: CapabilityFlags,
}

pub fn initiator_start<E: EntropySource>(
    local_static: &NoiseStaticKeypair,
    remote_static: &[u8; 32],
    capabilities: CapabilityFlags,
    entropy: &mut E,
) -> Result<(HandshakeMessage, InitiatorState), IdentityError> {
    let mut eph_secret = [0u8; 32];
    entropy.fill_bytes(&mut eph_secret)?;
    let eph_public = PublicKey::from(&StaticSecret::from(eph_secret)).to_bytes();

    let ck = derive_initial_ck_initiator(&eph_secret, local_static.secret_bytes(), remote_static);
    let mac = handshake_mac(&ck, capabilities.bits().to_le_bytes());

    let msg = HandshakeMessage {
        version: HANDSHAKE_VERSION,
        capabilities,
        ephemeral: eph_public,
        mac,
    };

    Ok((
        msg,
        InitiatorState {
            ck,
            ephemeral_secret: eph_secret,
            capabilities,
        },
    ))
}

pub fn responder_accept<E: EntropySource>(
    incoming: &HandshakeMessage,
    local_static: &NoiseStaticKeypair,
    remote_static: &[u8; 32],
    capabilities: CapabilityFlags,
    entropy: &mut E,
) -> Result<(HandshakeMessage, HandshakeKeys), IdentityError> {
    if incoming.version != HANDSHAKE_VERSION {
        return Err(IdentityError::InvalidChallenge);
    }

    let ck = derive_initial_ck_responder(incoming, local_static.secret_bytes(), remote_static);
    verify_mac(&ck, incoming.capabilities.bits().to_le_bytes(), incoming.mac)?;

    let mut eph_secret = [0u8; 32];
    entropy.fill_bytes(&mut eph_secret)?;
    let eph_public = PublicKey::from(&StaticSecret::from(eph_secret)).to_bytes();

    let shared = finalize_shared_secret_responder(
        &ck,
        &eph_secret,
        incoming.ephemeral,
        remote_static,
    );
    let manager = CapabilityManager::new(capabilities, incoming.capabilities);
    let negotiated = manager.negotiated();
    let mac = handshake_mac(&shared, negotiated.bits().to_le_bytes());

    let response = HandshakeMessage {
        version: HANDSHAKE_VERSION,
        capabilities: negotiated,
        ephemeral: eph_public,
        mac,
    };

    Ok((
        response,
        HandshakeKeys {
            shared_secret: shared,
            negotiated_capabilities: negotiated,
        },
    ))
}

pub fn initiator_finish(
    state: InitiatorState,
    response: &HandshakeMessage,
    local_static: &NoiseStaticKeypair,
    remote_static: &[u8; 32],
) -> Result<HandshakeKeys, IdentityError> {
    if response.version != HANDSHAKE_VERSION {
        return Err(IdentityError::InvalidChallenge);
    }

    let shared = finalize_shared_secret_initiator(
        &state.ck,
        state.ephemeral_secret,
        response.ephemeral,
        local_static.secret_bytes(),
    );
    let manager = CapabilityManager::new(state.capabilities, response.capabilities);
    let negotiated = manager.negotiated();
    verify_mac(&shared, negotiated.bits().to_le_bytes(), response.mac)?;

    Ok(HandshakeKeys {
        shared_secret: shared,
        negotiated_capabilities: negotiated,
    })
}

fn derive_initial_ck_initiator(
    eph_secret: &[u8; 32],
    local_static: &[u8; 32],
    remote_static: &[u8; 32],
) -> [u8; 32] {
    let dh1 = diffie_hellman_secret_public(eph_secret, remote_static);
    let dh2 = diffie_hellman_secret_public(local_static, remote_static);
    kdf(&[dh1, dh2], LABEL_INITIAL)
}

fn derive_initial_ck_responder(
    incoming: &HandshakeMessage,
    local_static: &[u8; 32],
    remote_static: &[u8; 32],
) -> [u8; 32] {
    let dh1 = diffie_hellman_secret_public(local_static, &incoming.ephemeral);
    let dh2 = diffie_hellman_secret_public(local_static, remote_static);
    kdf(&[dh1, dh2], LABEL_INITIAL)
}

fn finalize_shared_secret_responder(
    ck: &[u8; 32],
    local_ephemeral_secret: &[u8; 32],
    remote_ephemeral: [u8; 32],
    remote_static: &[u8; 32],
) -> [u8; 32] {
    let dh1 = diffie_hellman_secret_public(local_ephemeral_secret, remote_static);
    let dh2 = diffie_hellman_secret_public(local_ephemeral_secret, &remote_ephemeral);
    kdf_with_chain(ck, &[dh1, dh2], LABEL_FINAL)
}

fn finalize_shared_secret_initiator(
    ck: &[u8; 32],
    local_ephemeral_secret: [u8; 32],
    remote_ephemeral: [u8; 32],
    local_static: &[u8; 32],
) -> [u8; 32] {
    let dh1 = diffie_hellman_secret_public(local_static, &remote_ephemeral);
    let dh2 = diffie_hellman_secret_public(&local_ephemeral_secret, &remote_ephemeral);
    kdf_with_chain(ck, &[dh1, dh2], LABEL_FINAL)
}

fn diffie_hellman_secret_public(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*secret);
    let pk = PublicKey::from(*public);
    sk.diffie_hellman(&pk).to_bytes()
}

fn kdf(blocks: &[[u8; 32]], label: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(label).expect("label");
    for block in blocks {
        mac.update(block);
    }
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn kdf_with_chain(chain: &[u8; 32], blocks: &[[u8; 32]], label: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(label).expect("label");
    mac.update(chain);
    for block in blocks {
        mac.update(block);
    }
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn handshake_mac(key: &[u8; 32], message: [u8; 4]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("mac");
    mac.update(LABEL_MAC);
    mac.update(&message);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn verify_mac(key: &[u8; 32], message: [u8; 4], mac_value: [u8; 32]) -> Result<(), IdentityError> {
    let expected = handshake_mac(key, message);
    if subtle_constant_time_eq(&expected, &mac_value) {
        Ok(())
    } else {
        Err(IdentityError::VerificationFailed)
    }
}

fn subtle_constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
