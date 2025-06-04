//! # zkaleido-sp1-groth16-verifier
//!
//! This crate integrates SP1-based Groth16 proof verification.

mod conversion;
mod error;
mod types;
mod utils;
mod verification;
mod verifier;

pub use verifier::SP1Groth16Verifier;
