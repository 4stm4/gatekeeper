//! Обёртка поверх Noise-рукопожатия для обмена ZK-доказательствами по защищённому каналу.

use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::IdentityError;
use crate::handshake::{
    initiator_finish, initiator_start, responder_accept, CapabilityFlags, HandshakeKeys,
    HandshakeMessage, InitiatorState, NoiseStaticKeypair, RatchetRole, RatchetState,
};
use crate::identity::entropy::EntropySource;

type HmacSha256 = Hmac<Sha256>;

/// Итоговый защищённый канал после завершения Noise-рукопожатия.
pub struct SecureChannel {
    ratchet: RatchetState,
    send_counter: u64,
    recv_counter: u64,
    capabilities: CapabilityFlags,
}

/// Зашифрованное сообщение канала.
pub struct SecureMessage {
    pub counter: u64,
    pub payload: Vec<u8>,
    pub mac: [u8; 32],
}

/// Состояние инициатора между `start` и `finish`.
pub struct PendingInitiator {
    state: InitiatorState,
}

impl SecureChannel {
    fn from_keys(keys: HandshakeKeys, role: RatchetRole) -> Self {
        Self {
            ratchet: RatchetState::new(keys.shared_secret, role),
            send_counter: 0,
            recv_counter: 0,
            capabilities: keys.negotiated_capabilities,
        }
    }

    /// Возвращает согласованные capability-флаги.
    pub fn capabilities(&self) -> CapabilityFlags {
        self.capabilities
    }

    /// Шифрует и аутентифицирует полезную нагрузку.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> SecureMessage {
        let counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);
        let key = self.ratchet.next_send_key();
        encrypt_message(&key, counter, plaintext)
    }

    /// Расшифровывает сообщение, проверяя счётчики и MAC.
    pub fn decrypt(&mut self, message: &SecureMessage) -> Result<Vec<u8>, IdentityError> {
        if message.counter != self.recv_counter {
            return Err(IdentityError::ReplayDetected);
        }
        self.recv_counter = self.recv_counter.wrapping_add(1);
        let key = self.ratchet.next_recv_key();
        decrypt_message(&key, message)
    }
}

impl PendingInitiator {
    /// Завершает рукопожатие после получения ответа от респондента.
    pub fn finish(
        self,
        response: &HandshakeMessage,
        local_static: &NoiseStaticKeypair,
        remote_static: &[u8; 32],
    ) -> Result<SecureChannel, IdentityError> {
        let keys = initiator_finish(self.state, response, local_static, remote_static)?;
        Ok(SecureChannel::from_keys(keys, RatchetRole::Initiator))
    }
}

/// Запускает Noise-рукопожатие от лица инициатора.
pub fn start_initiator<E: EntropySource>(
    local_static: &NoiseStaticKeypair,
    remote_static: &[u8; 32],
    capabilities: CapabilityFlags,
    entropy: &mut E,
) -> Result<(HandshakeMessage, PendingInitiator), IdentityError> {
    let (msg, state) = initiator_start(local_static, remote_static, capabilities, entropy)?;
    Ok((msg, PendingInitiator { state }))
}

/// Обрабатывает входящее сообщение и формирует ответ респондента.
pub fn accept_responder<E: EntropySource>(
    incoming: &HandshakeMessage,
    local_static: &NoiseStaticKeypair,
    remote_static: &[u8; 32],
    capabilities: CapabilityFlags,
    entropy: &mut E,
) -> Result<(HandshakeMessage, SecureChannel), IdentityError> {
    let (response, keys) =
        responder_accept(incoming, local_static, remote_static, capabilities, entropy)?;
    Ok((response, SecureChannel::from_keys(keys, RatchetRole::Responder)))
}

fn encrypt_message(key: &[u8; 32], counter: u64, plaintext: &[u8]) -> SecureMessage {
    let mut payload = plaintext.to_vec();
    xor_keystream(key, counter, &mut payload);
    let mac = compute_mac(key, counter, &payload);
    SecureMessage {
        counter,
        payload,
        mac,
    }
}

fn decrypt_message(key: &[u8; 32], message: &SecureMessage) -> Result<Vec<u8>, IdentityError> {
    let expected = compute_mac(key, message.counter, &message.payload);
    if expected != message.mac {
        return Err(IdentityError::VerificationFailed);
    }
    let mut data = message.payload.clone();
    xor_keystream(key, message.counter, &mut data);
    Ok(data)
}

fn xor_keystream(key: &[u8; 32], counter: u64, data: &mut [u8]) {
    let mut block = 0u32;
    for chunk in data.chunks_mut(32) {
        let mut mac = HmacSha256::new_from_slice(key).expect("channel key");
        mac.update(&counter.to_le_bytes());
        mac.update(&block.to_le_bytes());
        let digest = mac.finalize().into_bytes();
        for (byte, mask) in chunk.iter_mut().zip(digest.iter()) {
            *byte ^= mask;
        }
        block = block.wrapping_add(1);
    }
}

fn compute_mac(key: &[u8; 32], counter: u64, data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("channel key");
    mac.update(&counter.to_le_bytes());
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
