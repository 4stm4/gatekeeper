use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::error::IdentityError;
use crate::identity::types::IdentityIdentifier;

use super::proof::{ZkProof, MAX_CHALLENGE_LEN};

#[derive(Clone, Copy)]
pub struct ChallengeTrackerConfig {
    pub capacity: usize,
    pub ttl_ticks: u64,
}

impl ChallengeTrackerConfig {
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

pub struct ChallengeTracker {
    config: ChallengeTrackerConfig,
    entries: Vec<ChallengeEntry>,
}

impl ChallengeTracker {
    pub fn new(config: ChallengeTrackerConfig) -> Self {
        Self {
            entries: Vec::with_capacity(config.capacity.max(1)),
            config,
        }
    }

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

        self.entries.push(ChallengeEntry { digest, timestamp: now });
        Ok(())
    }

    pub fn consume(&mut self, challenge: &[u8], now: u64) -> Result<(), IdentityError> {
        self.validate(challenge)?;
        self.purge(now);
        let digest = digest_challenge(challenge);
        if let Some(idx) = self.find_index(&digest) {
            self.entries.swap_remove(idx);
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
        if self.entries.is_empty() {
            return;
        }
        let mut oldest_idx = 0usize;
        let mut oldest_ts = self.entries[0].timestamp;
        for (idx, entry) in self.entries.iter().enumerate().skip(1) {
            if entry.timestamp < oldest_ts {
                oldest_idx = idx;
                oldest_ts = entry.timestamp;
            }
        }
        self.entries.swap_remove(oldest_idx);
    }
}

pub struct Verifier<'a> {
    domain: &'a [u8],
    tracker: ChallengeTracker,
}

impl<'a> Verifier<'a> {
    pub fn new(domain: &'a [u8], config: ChallengeTrackerConfig) -> Self {
        Self {
            domain,
            tracker: ChallengeTracker::new(config),
        }
    }

    pub fn tracker_mut(&mut self) -> &mut ChallengeTracker {
        &mut self.tracker
    }

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
