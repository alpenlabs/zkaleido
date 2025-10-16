use bn::{CurveError, FieldError, GroupError};
use thiserror::Error;

/// Error for buffer length mismatches during deserialization.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("Invalid buffer length for {context}: expected {expected} bytes, got {actual} bytes")]
pub struct BufferLengthError {
    pub context: &'static str,
    pub expected: usize,
    pub actual: usize,
}

/// Error for invalid data format during deserialization.
///
/// This occurs when:
/// - Invalid flag bits in compressed point encoding
/// - Hex string decoding fails
/// - Invalid infinity point encoding
/// - Other data format violations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("Invalid data format")]
pub struct InvalidDataFormatError;

/// Error for unsupported or invalid proof format.
///
/// This occurs when the proof length does not match any supported format
/// (compressed or uncompressed).
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("Invalid proof format: expected {expected_compressed} bytes (compressed) or {expected_uncompressed} bytes (uncompressed), got {actual} bytes")]
pub struct InvalidProofFormatError {
    pub expected_compressed: usize,
    pub expected_uncompressed: usize,
    pub actual: usize,
}

/// Error for invalid elliptic curve points.
///
/// This occurs when:
/// - Point does not lie on the curve
/// - Square root computation fails during decompression
/// - Point conversion from Jacobian to affine fails
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("Invalid elliptic curve point")]
pub struct InvalidPointError;

/// Unified serialization and deserialization error type.
#[derive(Error, Debug)]
pub enum SerializationError {
    /// Buffer length does not match expected size.
    #[error(transparent)]
    BufferLength(#[from] BufferLengthError),

    /// Data format is invalid or malformed.
    #[error(transparent)]
    InvalidFormat(#[from] InvalidDataFormatError),

    /// Proof format is invalid or unsupported.
    #[error(transparent)]
    InvalidProofFormat(#[from] InvalidProofFormatError),

    /// Elliptic curve point is invalid.
    #[error(transparent)]
    InvalidPoint(#[from] InvalidPointError),

    /// BN254 field element error.
    #[error("BN254 field error")]
    Field(FieldError),

    /// BN254 group element error.
    #[error("BN254 group error")]
    Group(GroupError),

    /// BN254 curve error.
    #[error("BN254 curve error")]
    Curve(CurveError),
}

// Manual From implementations for BN254 errors (they don't implement std::error::Error)
impl From<FieldError> for SerializationError {
    fn from(err: FieldError) -> Self {
        SerializationError::Field(err)
    }
}

impl From<GroupError> for SerializationError {
    fn from(err: GroupError) -> Self {
        SerializationError::Group(err)
    }
}

impl From<CurveError> for SerializationError {
    fn from(err: CurveError) -> Self {
        SerializationError::Curve(err)
    }
}

/// Errors specific to Groth16 proof verification.
#[derive(Debug, Error)]
pub enum Groth16Error {
    /// Proof verification failed.
    ///
    /// This occurs when the pairing check fails, indicating that the proof is invalid or does not
    /// correspond to the provided public inputs and verifying key.
    #[error("Proof verification failed")]
    VerificationFailed,

    /// Verifying key hash mismatch.
    ///
    /// This occurs when the hash of the verifying key embedded in the proof does not match the
    /// hash of the provided verifying key, indicating that the proof was generated with a
    /// different verifying key.
    #[error("Verifying key hash mismatch")]
    VkeyHashMismatch,

    /// Serialization or deserialization error.
    #[error(transparent)]
    Serialization(#[from] SerializationError),
}
