//! This crate provides a modular toolkit for building zero-knowledge proofs (ZKPs)
//! using a pluggable host architecture. By separating the concerns of input
//! construction, proof generation, and output processing, it allows you to flexibly
//! integrate various ZkVM backends and domain-specific logic.
//!
//! ## Overview
//!
//! - **[`ZkVmInputBuilder`]**: A trait for serializing and preparing input data (in a variety of
//!   formats) before handing it off to the ZkVM for proof generation.
//! - **[`ZkVmHost`]**: A trait for the "host," i.e., the environment or system responsible for
//!   generating and verifying proofs.
//! - **[`ZkVmProgram`]**: A high-level interface for logic-specific proof generation. Implementers
//!   define custom `Input` and `Output` types, then rely on a chosen host to actually run or verify
//!   the proof.
//! - **Error Handling**: A set of error enums (e.g., `ZkVmError`) provides comprehensive error
//!   reporting and integration with Rust's `thiserror` crate for detailed diagnostics.

use arbitrary::Arbitrary;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

mod env;
mod errors;
mod host;
mod input;
#[cfg(feature = "perf")]
mod perf;
mod program;
mod proof;
mod prover;
mod verifier;

pub use env::*;
pub use errors::*;
pub use host::*;
pub use input::*;
#[cfg(feature = "perf")]
pub use perf::*;
pub use program::*;
pub use proof::*;
pub use prover::*;
pub use verifier::*;

/// Represents the ZkVm host used for proof generation.
///
/// This enum identifies the ZkVm environment utilized to create a proof.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Default,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Arbitrary,
)]
pub enum ZkVm {
    /// SP1 ZKVM
    SP1,
    /// Risc0 ZKVM
    Risc0,
    /// Native ZKVM
    #[default]
    Native,
}
