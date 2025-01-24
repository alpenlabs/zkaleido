#[cfg(feature = "prover")]
mod host;
#[cfg(feature = "prover")]
pub use host::SP1Host;

#[cfg(feature = "prover")]
mod input;
#[cfg(feature = "prover")]
mod proof;
#[cfg(feature = "prover")]
pub use input::SP1ProofInputBuilder;

#[cfg(feature = "zkvm")]
mod env;
#[cfg(feature = "zkvm")]
pub use env::Sp1ZkVmEnv;

#[cfg(feature = "perf")]
pub mod perf;

mod groth16_verifier;
pub use groth16_verifier::*;
