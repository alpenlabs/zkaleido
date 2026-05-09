//! # zkaleido-sp1-adapter
//!
//! This crate integrates the [SP1](https://docs.succinct.xyz/docs/sp1/introduction) zero-knowledge proof
//! framework with the zkVM environment provided by [zkaleido](https://github.com/novifinancial/zkaleido).
//! It enables both the generation of SP1 proofs and the verification of SP1-based Groth16
//! proofs within a zkVM context.
//!
//! ## Performance reports
//!
//! With SP1 v6, the `perf` feature measures core, compressed, and Groth16 proofs through separate
//! SP1 SDK proof-mode runs. The compressed and Groth16 metrics are therefore independent end-to-end
//! proving measurements, not timings for converting a previously generated core proof into a
//! compressed proof or a previously generated compressed proof into a Groth16 proof.

mod host;
mod input;
mod proof;
mod prover;
mod remote_prover;
mod verifier;

pub use host::SP1Host;

#[cfg(feature = "perf")]
mod perf;
