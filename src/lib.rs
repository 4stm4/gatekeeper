#![no_std]

extern crate alloc;

#[macro_use]
mod logging;

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
