//! # zkaleido-risc0-adapter
//!
//! This crate integrates the [RISC Zero](https://www.risczero.com/) zero-knowledge proof
//! framework with the zkVM environment provided by [zkaleido](https://github.com/novifinancial/zkaleido).
//! It enables both the generation of RISC0 proofs and the verification of RISC0-based Groth16
//! proofs within a zkVM context.
//!
//! ## Features
//!
//! - **`prover`**: Enables proof generation via the RISC0 host and proof input builder. If you only
//!   need to perform verification, you can disable this feature.
mod host;
mod input;
mod proof;
mod prover;
mod verifier;

pub use host::Risc0Host;

#[cfg(feature = "perf")]
mod perf;
