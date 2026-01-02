use crate::error::IdentityError;
use crate::identity::access::ZkSecretRef;

use super::proof::{hash_with_length, transcript_challenge_scalar, ZkProof, MAX_CHALLENGE_LEN};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

pub trait ZkProver {
    fn prove(&self, sk: ZkSecretRef<'_>, challenge: &[u8]) -> Result<ZkProof, IdentityError>;
}

pub struct DeterministicSchnorrProver {
    domain: &'static [u8],
}

impl DeterministicSchnorrProver {
    pub const fn new(domain: &'static [u8]) -> Self {
        Self { domain }
    }

    fn derive_nonce(&self, secret: &[u8; 32], challenge: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(b"nonce");
        hash_with_length(&mut hasher, self.domain);
        hash_with_length(&mut hasher, challenge);
        hasher.update(secret);
        Scalar::from_hash(hasher)
    }
}

impl Default for DeterministicSchnorrProver {
    fn default() -> Self {
        Self {
            domain: b"zk-gatekeeper-schnorr-v1",
        }
    }
}

impl ZkProver for DeterministicSchnorrProver {
    fn prove(&self, sk: ZkSecretRef<'_>, challenge: &[u8]) -> Result<ZkProof, IdentityError> {
        if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_LEN {
            return Err(IdentityError::InvalidChallenge);
        }

        let mut secret_scalar = Scalar::from_bytes_mod_order(sk.secret.0);
        let public_point = (&secret_scalar * &ED25519_BASEPOINT_TABLE).compress();
        let public_bytes = public_point.to_bytes();

        let mut nonce_scalar = self.derive_nonce(&sk.secret.0, challenge);
        let commitment_point = (&nonce_scalar * &ED25519_BASEPOINT_TABLE).compress();
        let commitment_bytes = commitment_point.to_bytes();

        let mut challenge_scalar =
            transcript_challenge_scalar(self.domain, challenge, &public_bytes, &commitment_bytes);

        let mut response = Scalar::mul_add(challenge_scalar, secret_scalar, nonce_scalar);
        let proof = ZkProof::new(commitment_bytes, response.to_bytes());

        secret_scalar.zeroize();
        nonce_scalar.zeroize();
        challenge_scalar.zeroize();
        response.zeroize();

        Ok(proof)
    }
}
