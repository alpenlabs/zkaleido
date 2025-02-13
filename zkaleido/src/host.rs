use crate::{ZkVmProver, ZkVmVerifier};

/// A trait implemented by the prover ("host") of a zkVM program.
pub trait ZkVmHost: ZkVmProver + ZkVmVerifier {}
