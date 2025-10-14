//! # zkaleido-sp1-groth16-verifier
//!
//! This crate integrates SP1-based Groth16 proof verification.

#[cfg(feature = "borsh")]
mod borsh;
mod error;
pub mod hashes;
#[cfg(feature = "serde")]
mod serde;
mod types;
mod verification;
mod verifier;

pub use types::{
    constant::{
        GROTH16_PROOF_COMPRESSED_SIZE, GROTH16_PROOF_UNCOMPRESSED_SIZE,
        SP1_GROTH16_VK_COMPRESSED_SIZE, SP1_GROTH16_VK_UNCOMPRESSED_SIZE,
    },
    proof::Groth16Proof,
    vk::Groth16VerifyingKey,
};
pub use verification::verify_sp1_groth16_algebraic;
pub use verifier::{SP1Groth16Verifier, VK_HASH_PREFIX_LENGTH};
