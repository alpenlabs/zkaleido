//! # zkaleido-risc0-groth16-verifier
//!
//! This crate integrates RISC Zero-based Groth16 proof verification based on zkaleido traits.
mod sha256;
mod verifier;
mod errors;

pub use verifier::Risc0Groth16Verifier;
