//! # zkaleido-sp1-adapter
//!
//! This crate integrates the [SP1](https://docs.succinct.xyz/docs/sp1/introduction) zero-knowledge proof
//! framework with the zkVM environment provided by [zkaleido](https://github.com/novifinancial/zkaleido).
//! It enables both the generation of SP1 proofs and the verification of SP1-based Groth16
//! proofs within a zkVM context.
//!
//! ## Features
//!
//! - **`prover`**: Enables proof generation via the RISC0 host and proof input builder. If you only
//!   need to perform verification, you can disable this feature.
//! - **`mock`**: When enabled, the proof verification methods (`verify_native_proof` and
//!   `verify_groth16_receipt`) become no-ops. This is useful for testing or local development where
//!   you don't need to run the actual cryptographic verification:
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
#[cfg(feature = "remote-prover")]
mod remote_prover;
mod verifier;

pub use host::SP1Host;

#[cfg(feature = "perf")]
mod perf;
