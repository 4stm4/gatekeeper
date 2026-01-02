//! Абстракции для получения энтропии и их тестовые реализации.
//!
//! # Пример
//! ```
//! use zk_gatekeeper::identity::entropy::{EntropySource, MockEntropy, FallbackEntropy, PseudoEntropy};
//! use zk_gatekeeper::error::IdentityError;
//!
//! fn fill_random(src: &mut dyn EntropySource) -> Result<[u8; 16], IdentityError> {
//!     let mut out = [0u8; 16];
//!     src.fill_bytes(&mut out)?;
//!     Ok(out)
//! }
//!
//! let primary = MockEntropy::unavailable();
//! let secondary = PseudoEntropy::new([0x42; 32]);
//! let mut combined = FallbackEntropy::new(primary, secondary);
//! let bytes = fill_random(&mut combined).unwrap();
//! assert_ne!(bytes, [0u8; 16]);
//! ```
use core::cmp::min;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::IdentityError;

/// Источник энтропии, который умеет заполнять произвольный буфер.
pub trait EntropySource {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError>;
}

/// Простая детерминированная энтропия для тестов.
pub struct DummyEntropy;

impl EntropySource for DummyEntropy {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError> {
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }
        Ok(())
    }
}

/// Буферизированный источник, читающий данные из слайса.
pub struct MockEntropy<'a> {
    data: &'a [u8],
    cursor: usize,
    error: Option<IdentityError>,
}

impl<'a> MockEntropy<'a> {
    /// Создаёт источник, циклически читающий `data`.
    pub const fn from_slice(data: &'a [u8]) -> Self {
        Self {
            data,
            cursor: 0,
            error: None,
        }
    }

    /// Источник, который всегда возвращает `IdentityError::EntropyUnavailable`.
    pub const fn unavailable() -> Self {
        Self::with_error(IdentityError::EntropyUnavailable)
    }

    /// Источник, возвращающий произвольную ошибку.
    pub const fn with_error(error: IdentityError) -> Self {
        Self {
            data: &[],
            cursor: 0,
            error: Some(error),
        }
    }
}

impl<'a> EntropySource for MockEntropy<'a> {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError> {
        if let Some(err) = self.error {
            return Err(err);
        }

        if self.data.is_empty() {
            return Err(IdentityError::EntropyUnavailable);
        }

        for (i, byte) in out.iter_mut().enumerate() {
            let idx = (self.cursor + i) % self.data.len();
            *byte = self.data[idx];
        }
        self.cursor = (self.cursor + out.len()) % self.data.len();
        Ok(())
    }
}

/// Псевдослучайный поток на SHA-256, пригодный как fallback.
pub struct PseudoEntropy {
    state: [u8; 32],
    counter: u64,
}

impl PseudoEntropy {
    /// Инициализирует состояние с произвольным seed'ом.
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            state: seed,
            counter: 0,
        }
    }
}

impl EntropySource for PseudoEntropy {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError> {
        let mut produced = 0usize;
        while produced < out.len() {
            let mut hasher = Sha256::new();
            hasher.update(b"zk-gatekeeper-pseudo-entropy");
            hasher.update(&self.state);
            hasher.update(&self.counter.to_le_bytes());
            let digest = hasher.finalize();
            let mut block = [0u8; 32];
            block.copy_from_slice(&digest);
            let take = min(block.len(), out.len() - produced);
            out[produced..produced + take].copy_from_slice(&block[..take]);
            self.state.copy_from_slice(&block);
            self.counter = self.counter.wrapping_add(1);
            block.zeroize();
            produced += take;
        }
        Ok(())
    }
}

impl Drop for PseudoEntropy {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

/// Обёртка, которая сначала пробует primary-источник, а затем fallback.
pub struct FallbackEntropy<P, S> {
    primary: P,
    secondary: S,
}

impl<P, S> FallbackEntropy<P, S> {
    /// Создаёт failover из двух источников.
    pub const fn new(primary: P, secondary: S) -> Self {
        Self { primary, secondary }
    }
}

impl<P, S> EntropySource for FallbackEntropy<P, S>
where
    P: EntropySource,
    S: EntropySource,
{
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError> {
        match self.primary.fill_bytes(out) {
            Ok(()) => Ok(()),
            Err(IdentityError::EntropyUnavailable) => self.secondary.fill_bytes(out),
            Err(err) => Err(err),
        }
    }
}
