//! # zkaleido-sp1-groth16-verifier
//!
//! This crate integrates SP1-based Groth16 proof verification.

mod error;
// mod gnark_conversion;
mod types;
mod utils;
mod verification;
mod verifier;

pub use verifier::SP1Groth16Verifier;
