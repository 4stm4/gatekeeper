use alloc::vec::Vec;

use crate::error::IdentityError;
use crate::identity::types::{IdentityIdentifier, IdentityState};
use crate::zk::proof::{ZkProof, ZK_PROOF_LEN};
use crate::zk::prover::{DeterministicSchnorrProver, ZkProver};

pub const BLOB_PROOF_DOMAIN: &[u8] = b"zk-gatekeeper-blob-v1";

#[derive(Clone, Copy)]
pub struct BlobFetchChallenge {
    pub blob_id: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Clone)]
pub struct BlobFetchRequest {
    pub blob_id: [u8; 32],
    pub nonce: [u8; 32],
    pub proof: [u8; ZK_PROOF_LEN],
}

#[derive(Clone, Copy)]
pub struct BlobAccessEntry {
    pub blob_id: [u8; 32],
    pub identity: IdentityIdentifier,
    pub public_key: [u8; 32],
}

pub struct BlobAccessGate {
    entries: Vec<BlobAccessEntry>,
    domain: &'static [u8],
}

pub struct BlobAccessGrant {
    pub blob_id: [u8; 32],
    pub identity: IdentityIdentifier,
}

impl BlobFetchChallenge {
    pub fn encode(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.blob_id);
        out[32..].copy_from_slice(&self.nonce);
        out
    }
}

impl BlobFetchRequest {
    pub fn new(proof: ZkProof, challenge: &BlobFetchChallenge) -> Self {
        Self {
            blob_id: challenge.blob_id,
            nonce: challenge.nonce,
            proof: *proof.as_bytes(),
        }
    }
}

pub struct BlobIdentityProver<'a, P: ZkProver> {
    identity: &'a IdentityState,
    prover: P,
}

impl<'a> BlobIdentityProver<'a, DeterministicSchnorrProver> {
    pub fn new(identity: &'a IdentityState) -> Self {
        Self {
            identity,
            prover: DeterministicSchnorrProver::new(BLOB_PROOF_DOMAIN),
        }
    }
}

impl<'a, P: ZkProver> BlobIdentityProver<'a, P> {
    pub fn prove(&self, challenge: &BlobFetchChallenge) -> Result<BlobFetchRequest, IdentityError> {
        let challenge_bytes = challenge.encode();
        let proof = self.identity.prove_with(&self.prover, &challenge_bytes)?;
        Ok(BlobFetchRequest::new(proof, challenge))
    }
}

impl BlobAccessGate {
    pub fn new(domain: &'static [u8]) -> Self {
        Self {
            entries: Vec::new(),
            domain,
        }
    }

    pub fn register(&mut self, entry: BlobAccessEntry) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.blob_id == entry.blob_id && e.identity == entry.identity)
        {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    pub fn revoke(&mut self, blob_id: &[u8; 32], identity: IdentityIdentifier) {
        if let Some(idx) = self
            .entries
            .iter()
            .position(|e| e.blob_id == *blob_id && e.identity == identity)
        {
            self.entries.swap_remove(idx);
        }
    }

    pub fn verify(
        &self,
        challenge: &BlobFetchChallenge,
        request: &BlobFetchRequest,
    ) -> Result<BlobAccessGrant, IdentityError> {
        if challenge.blob_id != request.blob_id || challenge.nonce != request.nonce {
            return Err(IdentityError::InvalidChallenge);
        }

        let challenge_bytes = challenge.encode();
        let proof = ZkProof::from_bytes(&request.proof).ok_or(IdentityError::VerificationFailed)?;

        for entry in &self.entries {
            if entry.blob_id != request.blob_id {
                continue;
            }
            if proof.verify(self.domain, &challenge_bytes, &entry.public_key) {
                return Ok(BlobAccessGrant {
                    blob_id: entry.blob_id,
                    identity: entry.identity,
                });
            }
        }

        Err(IdentityError::VerificationFailed)
    }
}
