//! # zkaleido-sp1-adapter
//!
//! This crate integrates the [SP1](https://docs.succinct.xyz/docs/sp1/introduction) zero-knowledge proof
//! framework with the zkVM environment provided by [zkaleido](https://github.com/novifinancial/zkaleido).
//! It enables both the generation of SP1 proofs and the verification of SP1-based Groth16
//! proofs within a zkVM context.

mod config;
mod host;
mod input;
mod proof;
mod prover;
mod remote_prover;
mod verifier;

pub use config::SP1HostConfig;
pub use host::SP1Host;
