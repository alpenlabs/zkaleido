//! # zkaleido-risc0-guest-env
//!
//! This crate serves as the SP1 implementation of `ZkVmEnv`, enabling guest applications to
//! interact with the host environment seamlessly by receiving inputs and committing outputs.
//!
//! ## Features
//!
//! - **zkvm-verify**: Activates the SP1 proof recursive verification logic using the
//!   `sp1-zkvm/verify` adapter along with the `sha2` crate for cryptographic verification. When
//!   enabled, `verify_native_proof` computes a SHA256 digest of the public values and verifies the
//!   SP1 proof against the provided verification key digest.
//!
//! - **mock-verify**: Provides a no-op verification stub for testing purposes. When enabled, this
//!   feature bypasses the actual cryptographic verification.
//!
//! If neither feature is enabled, calling `verify_native_proof` will panic.

mod env;
pub use env::Sp1ZkVmEnv;
pub use sp1_zkvm::entrypoint;
