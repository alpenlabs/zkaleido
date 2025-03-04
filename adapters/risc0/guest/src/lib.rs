//! # zkaleido-risc0-guest-env
//!
//! This crate serves as the RISC Zero implementation of `ZkVmEnv`, enabling guest applications to
//! interact with the host environment seamlessly by receiving inputs and committing outputs.

mod env;
pub use env::Risc0ZkVmEnv;
pub use risc0_zkvm::guest::entry;
