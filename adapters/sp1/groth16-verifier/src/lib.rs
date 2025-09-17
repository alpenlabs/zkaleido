//! # zkaleido-sp1-groth16-verifier
//!
//! This crate integrates SP1-based Groth16 proof verification.

mod error;
mod types;
pub mod hashes;
mod verification;
mod verifier;

pub use types::{proof::Groth16Proof, vk::Groth16VerifyingKey};
pub use verification::verify_sp1_groth16_algebraic;
pub use verifier::SP1Groth16Verifier;
