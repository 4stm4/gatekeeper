//! Challenge-трекер и verifier для ZK-доказательств.
//!
//! # Пример
//! ```
//! use zk_gatekeeper::zk::verifier::{ChallengeTrackerConfig, Verifier};
//! use zk_gatekeeper::identity::types::{DeviceId, IdentityState, RootKey};
//! use zk_gatekeeper::zk::prover::{DeterministicSchnorrProver, ZkProver};
//!
//! let state = IdentityState::from_root(RootKey([7; 32]), DeviceId([1; 16])).unwrap();
//! let challenge = b"demo";
//! let mut verifier = Verifier::new(b"zk-gatekeeper-schnorr-v1", ChallengeTrackerConfig::default());
//! verifier.tracker_mut().register(challenge, 1).unwrap();
//! let proof = state.prove_with(&DeterministicSchnorrProver::default(), challenge).unwrap();
//! let pk = state.public_key().into_bytes();
//! let id = state.identifier();
//! verifier.verify(&id, &pk, challenge, 2, &proof).unwrap();
//! ```
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::error::IdentityError;
use crate::identity::types::IdentityIdentifier;

use super::proof::{ZkProof, MAX_CHALLENGE_LEN};

/// Параметры ChallengeTracker (размер + TTL).
#[derive(Clone, Copy)]
pub struct ChallengeTrackerConfig {
    pub capacity: usize,
    pub ttl_ticks: u64,
}

impl ChallengeTrackerConfig {
    /// Создаёт конфигурацию с указанными лимитами.
    pub const fn new(capacity: usize, ttl_ticks: u64) -> Self {
        Self {
            capacity,
            ttl_ticks,
        }
    }
}

impl Default for ChallengeTrackerConfig {
    fn default() -> Self {
        Self::new(64, 60_000)
    }
}

#[derive(Clone)]
struct ChallengeEntry {
    digest: [u8; 32],
    timestamp: u64,
}

/// Регистрирует и инвалидирует challenge для защиты от replay.
pub struct ChallengeTracker {
    config: ChallengeTrackerConfig,
    entries: VecDeque<ChallengeEntry>,
}

impl ChallengeTracker {
    /// Создаёт новый трекер.
    pub fn new(config: ChallengeTrackerConfig) -> Self {
        Self {
            entries: VecDeque::with_capacity(config.capacity.max(1)),
            config,
        }
    }

    /// Регистрирует challenge и момент времени `now`.
    pub fn register(&mut self, challenge: &[u8], now: u64) -> Result<(), IdentityError> {
        self.validate(challenge)?;
        self.purge(now);
        let digest = digest_challenge(challenge);
        if self.find_index(&digest).is_some() {
            return Err(IdentityError::ReplayDetected);
        }

        if self.config.capacity == 0 {
            return Err(IdentityError::ChallengeStoreFull);
        }

        if self.entries.len() >= self.config.capacity {
            self.evict_oldest();
        }

        self.entries.push_back(ChallengeEntry {
            digest,
            timestamp: now,
        });
        Ok(())
    }

    /// Помечает challenge использованным.
    pub fn consume(&mut self, challenge: &[u8], now: u64) -> Result<(), IdentityError> {
        self.validate(challenge)?;
        self.purge(now);
        let digest = digest_challenge(challenge);
        if let Some(idx) = self.find_index(&digest) {
            self.entries.remove(idx);
            Ok(())
        } else {
            Err(IdentityError::ChallengeNotRegistered)
        }
    }

    fn validate(&self, challenge: &[u8]) -> Result<(), IdentityError> {
        if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_LEN {
            Err(IdentityError::InvalidChallenge)
        } else {
            Ok(())
        }
    }

    fn purge(&mut self, now: u64) {
        if self.config.ttl_ticks == 0 {
            return;
        }
        let ttl = self.config.ttl_ticks;
        self.entries
            .retain(|entry| now.saturating_sub(entry.timestamp) <= ttl);
    }

    fn find_index(&self, digest: &[u8; 32]) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.digest == *digest)
    }

    fn evict_oldest(&mut self) {
        if let Some(entry) = self.entries.pop_front() {
            zk_log_debug!("ChallengeTracker evicted digest={:x?}", entry.digest);
        }
    }
}

pub struct Verifier<'a> {
    domain: &'a [u8],
    tracker: ChallengeTracker,
}

impl<'a> Verifier<'a> {
    /// Создаёт verifier с заданным доменом и параметрами.
    pub fn new(domain: &'a [u8], config: ChallengeTrackerConfig) -> Self {
        Self {
            domain,
            tracker: ChallengeTracker::new(config),
        }
    }

    /// Возвращает изменяемую ссылку на трекер (регистрация challenge).
    pub fn tracker_mut(&mut self) -> &mut ChallengeTracker {
        &mut self.tracker
    }

    /// Проверяет `proof` относительно идентификатора, публичного ключа и challenge.
    pub fn verify(
        &mut self,
        identity: &IdentityIdentifier,
        public_key: &[u8; 32],
        challenge: &[u8],
        now: u64,
        proof: &ZkProof,
    ) -> Result<(), IdentityError> {
        if !identity.matches(public_key) {
            return Err(IdentityError::InvalidPublicKey);
        }

        self.tracker.consume(challenge, now)?;

        if proof.verify(self.domain, challenge, public_key) {
            Ok(())
        } else {
            Err(IdentityError::VerificationFailed)
        }
    }
}

fn digest_challenge(challenge: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zk-gatekeeper-challenge");
    hasher.update(&(challenge.len() as u16).to_le_bytes());
    hasher.update(challenge);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
