use alloc::vec::Vec;
use core::convert::TryInto;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

pub const ZK_PROOF_LEN: usize = 64;
pub const MAX_CHALLENGE_LEN: usize = 64;

pub struct ZkProof {
    bytes: [u8; ZK_PROOF_LEN],
}

impl ZkProof {
    pub fn new(commitment: [u8; 32], response: [u8; 32]) -> Self {
        let mut bytes = [0u8; ZK_PROOF_LEN];
        bytes[..32].copy_from_slice(&commitment);
        bytes[32..].copy_from_slice(&response);
        Self { bytes }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ZK_PROOF_LEN {
            return None;
        }
        let mut data = [0u8; ZK_PROOF_LEN];
        data.copy_from_slice(bytes);
        Some(Self { bytes: data })
    }

    pub fn as_bytes(&self) -> &[u8; ZK_PROOF_LEN] {
        &self.bytes
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    pub fn commitment(&self) -> [u8; 32] {
        self.bytes[..32].try_into().unwrap()
    }

    pub fn response(&self) -> [u8; 32] {
        self.bytes[32..].try_into().unwrap()
    }

    pub fn verify(
        &self,
        domain: &[u8],
        challenge: &[u8],
        public_key: &[u8; 32],
    ) -> bool {
        if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_LEN {
            return false;
        }

        let pk_point = match CompressedEdwardsY(*public_key).decompress() {
            Some(point) => point,
            None => return false,
        };

        let commitment_bytes = self.commitment();
        let commitment_point = match CompressedEdwardsY(commitment_bytes).decompress() {
            Some(point) => point,
            None => return false,
        };

        let response_bytes = self.response();
        let mut response_scalar = match Scalar::from_canonical_bytes(response_bytes) {
            Some(scalar) => scalar,
            None => return false,
        };

        let mut challenge_scalar =
            transcript_challenge_scalar(domain, challenge, public_key, &commitment_bytes);

        let lhs = &response_scalar * &ED25519_BASEPOINT_TABLE;
        let rhs = commitment_point + challenge_scalar * pk_point;
        let valid = lhs == rhs;

        response_scalar.zeroize();
        challenge_scalar.zeroize();

        valid
    }
}

pub(crate) fn transcript_challenge_scalar(
    domain: &[u8],
    challenge: &[u8],
    public_key: &[u8; 32],
    commitment: &[u8; 32],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"challenge");
    hash_with_length(&mut hasher, domain);
    hash_with_length(&mut hasher, challenge);
    hasher.update(public_key);
    hasher.update(commitment);
    Scalar::from_hash(hasher)
}

pub(crate) fn hash_with_length(hasher: &mut Sha512, data: &[u8]) {
    let len = data.len() as u16;
    hasher.update(len.to_le_bytes());
    hasher.update(data);
}
