use thiserror::Error;

/// Errors that can occur during Risc0 Groth16 proof verification.
///
/// These errors represent the various failure modes that can occur when
/// setting up a verifier or validating a proof.
#[derive(Error, Debug)]
pub enum Risc0VerifierError {
    /// Failed to convert a digest or control root to a valid field element.
    ///
    /// This typically occurs when the input bytes don't represent a valid
    /// element in the BN254 scalar field, or when hex decoding fails.
    #[error("failed to convert bytes to valid field element: {0}")]
    InvalidFr(String),

    /// Failed to split a digest into two field elements.
    ///
    /// This error occurs when a 32-byte digest cannot be properly divided
    /// into two 16-byte halves that represent valid field elements.
    #[error("failed to split digest into field elements: {0}")]
    SplitDigest(String),

    /// Error parsing the proof data into a valid Groth16 seal.
    ///
    /// This indicates that the provided proof bytes are malformed,
    /// corrupted, or not in the expected Groth16 format.
    #[error("failed to parse proof data: {0}")]
    ProofParse(String),

    /// Error occurred while constructing the Groth16 verifier.
    ///
    /// This can happen if the verifying key is invalid, the public inputs
    /// are malformed, or there's an internal error in the verifier setup.
    #[error("failed to create Groth16 verifier instance: {0}")]
    VerifierCreation(String),

    /// The proof verification process failed.
    ///
    /// This means the proof is invalid - either it was generated for different
    /// public inputs, uses a different program, or is simply not a valid proof.
    #[error("proof verification failed: {0}")]
    Verification(String),
}
