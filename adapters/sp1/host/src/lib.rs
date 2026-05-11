//! # zkaleido-sp1-adapter
//!
//! This crate integrates the [SP1](https://docs.succinct.xyz/docs/sp1/introduction) zero-knowledge proof
//! framework with the zkVM environment provided by [zkaleido](https://github.com/novifinancial/zkaleido).
//! It enables both the generation of SP1 proofs and the verification of SP1-based Groth16
//! proofs within a zkVM context.
//!
//! ## Configuration
//!
//! [`SP1HostConfig::from_env`] (also used by [`SP1HostConfig::default`] and
//! [`SP1Host::init`]) reads the following adapter-specific environment
//! variables. These are *not* SP1 SDK envs — they configure this crate's
//! wrapping of the network prover:
//!
//! - `SP1_PROOF_STRATEGY` — fulfillment strategy for the network prover. One of `auction`
//!   (default), `hosted`, or `reserved`. An unparsable value panics rather than silently routing to
//!   the wrong cluster.
//! - `SP1_DEADLINE_ENV_MS` — deadline forwarded to network proof requests, in milliseconds. Unset
//!   or unparsable defers to the SP1 SDK default (auto-derived from the gas limit).
//! - `SP1_NETWORK_POLL_ENV_MS` — poll cadence for `get_status` on the synchronous network proving
//!   path, in milliseconds. Defaults to `1000` (1 second) when unset or unparsable.
//!
//! Upstream SP1 envs such as `SP1_PROVER` (prover backend) and `ZKVM_MOCK`
//! (mock mode) are read by the SP1 SDK itself and continue to apply; see
//! the SP1 docs for their semantics.

mod config;
mod host;
mod input;
mod proof;
mod prover;
mod remote_prover;
mod verifier;

pub use config::SP1HostConfig;
pub use host::SP1Host;
