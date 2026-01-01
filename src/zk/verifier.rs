use sha2::{Digest, Sha256};

use crate::error::IdentityError;
use crate::identity::types::IdentityIdentifier;

use super::proof::{ZkProof, MAX_CHALLENGE_LEN};

pub struct ChallengeTracker<const N: usize> {
    digests: [[u8; 32]; N],
    occupied: [bool; N],
}

impl<const N: usize> ChallengeTracker<N> {
    pub const fn new() -> Self {
        Self {
            digests: [[0u8; 32]; N],
            occupied: [false; N],
        }
    }

    pub fn register(&mut self, challenge: &[u8]) -> Result<(), IdentityError> {
        if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_LEN {
            return Err(IdentityError::InvalidChallenge);
        }

        let digest = digest_challenge(challenge);

        if self.find(&digest).is_some() {
            return Err(IdentityError::ReplayDetected);
        }

        let slot = self.free_slot().ok_or(IdentityError::ChallengeStoreFull)?;
        self.digests[slot] = digest;
        self.occupied[slot] = true;
        Ok(())
    }

    pub fn consume(&mut self, challenge: &[u8]) -> Result<(), IdentityError> {
        if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_LEN {
            return Err(IdentityError::InvalidChallenge);
        }

        let digest = digest_challenge(challenge);

        if let Some(idx) = self.find(&digest) {
            self.digests[idx] = [0u8; 32];
            self.occupied[idx] = false;
            Ok(())
        } else {
            Err(IdentityError::ChallengeNotRegistered)
        }
    }

    fn find(&self, digest: &[u8; 32]) -> Option<usize> {
        for (idx, stored) in self.digests.iter().enumerate() {
            if self.occupied[idx] && stored == digest {
                return Some(idx);
            }
        }
        None
    }

    fn free_slot(&mut self) -> Option<usize> {
        for idx in 0..N {
            if !self.occupied[idx] {
                return Some(idx);
            }
        }
        None
    }
}

pub struct Verifier<'a, const N: usize> {
    domain: &'a [u8],
    tracker: ChallengeTracker<N>,
}

impl<'a, const N: usize> Verifier<'a, N> {
    pub const fn new(domain: &'a [u8]) -> Self {
        Self {
            domain,
            tracker: ChallengeTracker::new(),
        }
    }

    pub fn tracker_mut(&mut self) -> &mut ChallengeTracker<N> {
        &mut self.tracker
    }

    pub fn verify(
        &mut self,
        identity: &IdentityIdentifier,
        public_key: &[u8; 32],
        challenge: &[u8],
        proof: &ZkProof,
    ) -> Result<(), IdentityError> {
        if !identity.matches(public_key) {
            return Err(IdentityError::InvalidPublicKey);
        }

        self.tracker.consume(challenge)?;

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
