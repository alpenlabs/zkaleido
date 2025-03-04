//! # zkaleido-risc0-host
//!
//! This crate integrates the [RISC Zero](https://www.risczero.com/) zeroframework
//! with the zkVM traits defined by [zkaleido](https://github.com/alpenlabs/zkaleido)
//! on the host side.

mod host;
mod input;
mod proof;
mod prover;
mod verifier;

pub use host::Risc0Host;

#[cfg(feature = "perf")]
mod perf;
