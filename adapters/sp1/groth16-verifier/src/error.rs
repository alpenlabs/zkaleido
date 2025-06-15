use bn::{CurveError, FieldError, GroupError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // Input Errors
    #[error("Invalid witness")]
    InvalidWitness,
    #[error("Invalid x length")]
    InvalidXLength,
    #[error("Invalid data")]
    InvalidData,
    #[error("Invalid point in subgroup check")]
    InvalidPoint,

    // Conversion Errors
    #[error("Failed to get Fr from random bytes")]
    FailedToGetFrFromRandomBytes,

    // External Library Errors
    #[error("BN254 Field Error")]
    Field(FieldError),
    #[error("BN254 Group Error")]
    Group(GroupError),
    #[error("BN254 Curve Error")]
    Curve(CurveError),

    // SP1 Errors
    #[error("Invalid program vkey hash")]
    InvalidProgramVkeyHash,
}

#[derive(Debug, Error)]
pub enum Groth16Error {
    #[error("Proof verification failed")]
    ProofVerificationFailed,
    #[error("Process verifying key failed")]
    ProcessVerifyingKeyFailed,
    #[error("Prepare inputs failed")]
    PrepareInputsFailed,
    #[error("General error")]
    GeneralError(#[from] crate::error::Error),
    #[error("Groth16 vkey hash mismatch")]
    Groth16VkeyHashMismatch,
}
