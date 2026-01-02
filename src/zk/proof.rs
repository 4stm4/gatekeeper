//! Сериализуемый формат Schnorr-доказательства (commitment + response) и проверка.

use alloc::vec::Vec;
use core::convert::TryInto;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// Текущая версия двоичного формата.
pub const ZK_PROOF_VERSION: u8 = 1;
/// Размер заголовка (версия + длина полезной нагрузки).
pub const ZK_PROOF_HEADER_LEN: usize = 2;
/// Размер закомпрессированного коммитмента.
pub const ZK_COMMITMENT_LEN: usize = 32;
/// Размер скалярного ответа.
pub const ZK_RESPONSE_LEN: usize = 32;
/// Полный размер доказательства в байтах.
pub const ZK_PROOF_LEN: usize = ZK_PROOF_HEADER_LEN + ZK_COMMITMENT_LEN + ZK_RESPONSE_LEN;
/// Допустимая длина публичного challenge.
pub const MAX_CHALLENGE_LEN: usize = 64;

/// Минимальное представление Schnorr-доказательства, пригодное для prover/verifier.
pub struct ZkProof {
    bytes: [u8; ZK_PROOF_LEN],
}

impl ZkProof {
    /// Собирает доказательство из коммитмента и ответа.
    pub fn new(commitment: [u8; 32], response: [u8; 32]) -> Self {
        let mut bytes = [0u8; ZK_PROOF_LEN];
        bytes[0] = ZK_PROOF_VERSION;
        bytes[1] = (ZK_COMMITMENT_LEN + ZK_RESPONSE_LEN) as u8;
        bytes[ZK_PROOF_HEADER_LEN..ZK_PROOF_HEADER_LEN + ZK_COMMITMENT_LEN]
            .copy_from_slice(&commitment);
        bytes[ZK_PROOF_HEADER_LEN + ZK_COMMITMENT_LEN..].copy_from_slice(&response);
        Self { bytes }
    }

    /// Проверяет формат и создаёт структуру из среза.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ZK_PROOF_LEN {
            return None;
        }
        if bytes[0] != ZK_PROOF_VERSION {
            return None;
        }
        if bytes[1] as usize != ZK_COMMITMENT_LEN + ZK_RESPONSE_LEN {
            return None;
        }
        let mut data = [0u8; ZK_PROOF_LEN];
        data.copy_from_slice(bytes);
        Some(Self { bytes: data })
    }

    /// Возвращает внутреннее представление без копирования.
    pub fn as_bytes(&self) -> &[u8; ZK_PROOF_LEN] {
        &self.bytes
    }

    /// Копирует доказательство в `Vec` для FFI/host API.
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    /// Возвращает версию формата.
    pub fn version(&self) -> u8 {
        self.bytes[0]
    }

    /// Возвращает коммитмент R (compressed Edwards Y).
    pub fn commitment(&self) -> [u8; 32] {
        self.bytes[ZK_PROOF_HEADER_LEN..ZK_PROOF_HEADER_LEN + ZK_COMMITMENT_LEN]
            .try_into()
            .unwrap()
    }

    /// Возвращает ответ `s`.
    pub fn response(&self) -> [u8; 32] {
        self.bytes[ZK_PROOF_HEADER_LEN + ZK_COMMITMENT_LEN..]
            .try_into()
            .unwrap()
    }

    /// Проверяет Schnorr-реляцию относительно домена, challenge и публичного ключа.
    pub fn verify(&self, domain: &[u8], challenge: &[u8], public_key: &[u8; 32]) -> bool {
        if self.version() != ZK_PROOF_VERSION {
            return false;
        }
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

/// Вычисляет Fiat-Shamir challenge = H(domain || challenge || pk || commitment).
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

/// Хэширует данные с префиксом длины (16 бит little-endian).
pub(crate) fn hash_with_length(hasher: &mut Sha512, data: &[u8]) {
    let len = data.len() as u16;
    hasher.update(len.to_le_bytes());
    hasher.update(data);
}
