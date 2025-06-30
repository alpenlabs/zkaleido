//! # zkaleido-risc0-groth16-verifier
//!
//! This crate integrates RISC Zero-based Groth16 proof verification based on zkaleido traits.
mod errors;
mod sha256;
mod verifier;

pub use verifier::Risc0Groth16Verifier;
