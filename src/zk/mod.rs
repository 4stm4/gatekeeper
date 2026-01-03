//! ZK-подсистема: prover, proof-формат и verifier.
#[cfg(feature = "handshake")]
pub mod handshake;
pub mod proof;
pub mod prover;
pub mod verifier;
