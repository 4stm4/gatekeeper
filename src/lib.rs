#![no_std]

extern crate alloc;

#[cfg(feature = "contacts")]
pub mod contacts;
pub mod error;
#[cfg(feature = "handshake")]
pub mod handshake;
pub mod identity;
pub mod platform;
#[cfg(any(
    feature = "flash-storage",
    feature = "secure-storage",
    feature = "storage-gate"
))]
pub mod storage;
pub mod zk;
