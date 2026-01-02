//! Управление цифровой личностью: генерация ключей, хранение seed-фразы,
//! восстановление и мульти-девайсная привязка.
//!
//! # Пример
//! ```
//! use zk_gatekeeper::identity::init::init_identity;
//! use zk_gatekeeper::identity::types::DeviceId;
//! use zk_gatekeeper::identity::entropy::DummyEntropy;
//!
//! let mut entropy = DummyEntropy;
//! let device = DeviceId([1u8; 16]);
//! let identity = init_identity(&mut entropy, device).unwrap();
//! assert_eq!(identity.device_id(), device);
//! ```
pub mod access;
pub mod entropy;
pub mod hkdf;
pub mod init;
pub mod keys;
pub mod link;
#[cfg(feature = "flash-storage")]
pub mod persist;
pub mod seed;
pub mod types;
