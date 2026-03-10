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

use std::fmt::{Display, Formatter, Result};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "serde")]
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
mod remote_prover;
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
pub use remote_prover::*;
pub use verifier::*;

/// Represents the ZkVm host used for proof generation.
///
/// This enum identifies the ZkVm environment utilized to create a proof.
#[derive(Debug, Clone, Copy, PartialEq, Default, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh", borsh(use_discriminant = true))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[repr(u8)]
pub enum ZkVm {
    /// Native ZKVM
    #[default]
    Native = 0,
    /// SP1 ZKVM
    SP1 = 1,
    /// Risc0 ZKVM
    Risc0 = 2,
}

impl Display for ZkVm {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let s = match self {
            ZkVm::SP1 => "SP1",
            ZkVm::Risc0 => "Risc0",
            ZkVm::Native => "Native",
        };
        write!(f, "{}", s)
    }
}

impl TryFrom<u8> for ZkVm {
    type Error = ZkVmError;

    fn try_from(tag: u8) -> ZkVmResult<Self> {
        match tag {
            0 => Ok(ZkVm::Native),
            1 => Ok(ZkVm::SP1),
            2 => Ok(ZkVm::Risc0),
            _ => Err(ZkVmError::Other(format!("unknown zkvm tag: {tag}"))),
        }
    }
}
