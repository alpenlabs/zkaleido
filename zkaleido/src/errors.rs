use std::fmt::{Debug, Display};

#[cfg(feature = "borsh")]
use borsh::io::Error as BorshIoError;
use thiserror::Error;

use crate::{ProofType, ZkVm};

/// A convenient alias for results in the ZkVM.
pub type ZkVmResult<T> = Result<T, ZkVmError>;

/// General ZkVM error types.
///
/// Every error is either permanent or transient, and
/// [`is_permanent`](Self::is_permanent) says which. The rule is:
///
/// - **Permanent**: the cause is in the request, meaning the program, its input, or the requested
///   proof. The same request fails the same way on any healthy machine, so retrying cannot help.
/// - **Transient**: the cause is in the environment, meaning the machine, its resources, the
///   network, or a remote prover. A later attempt may succeed.
///
/// An error is permanent only when we know its cause is in the request. If we
/// cannot tell, it is transient. A wrong transient costs a few retries, which
/// the caller's retry budget bounds. A wrong permanent drops a request that
/// would have succeeded and needs a manual fix.
///
/// A fault in the environment that does not go away, such as a missing API
/// key, is still transient. It uses up the retry budget and then fails.
#[derive(Debug, Error)]
pub enum ZkVmError {
    /// This error is returned when execution fails.
    /// It wraps the underlying [`ZkVmExecutionError`], which says whether the
    /// guest or the host is at fault.
    #[error("Execution failed: {0}")]
    ExecutionError(#[from] ZkVmExecutionError),

    /// Network (or RPC) error that can occur while using prover network.
    #[error("Network error: {0}")]
    NetworkRetryableError(String),

    /// This error is returned when proof generation fails for any reason.
    #[error("Proof generation failed: {0}")]
    ProofGenerationError(String),

    /// This error is returned when proof verification fails for any reason.
    #[error("Proof verification failed: {0}")]
    ProofVerificationError(String),

    /// This error indicates that input validation has failed.
    /// It wraps the underlying [`ZkVmInputError`].
    #[error("Input validation failed: {0}")]
    InvalidInput(#[from] ZkVmInputError),

    /// This error is returned when ELF validation fails.
    #[error("ELF validation failed: {0}")]
    InvalidELF(String),

    /// This error occurs if the verification key is invalid.
    /// It wraps the underlying [`ZkVmVerifyingKeyError`].
    #[error("Invalid verification key: {0}")]
    InvalidVerifyingKey(#[from] ZkVmVerifyingKeyError),

    /// This error occurs if the proof receipt is invalid.
    /// It wraps the underlying [`ZkVmProofError`].
    #[error("Invalid proof receipt: {0}")]
    InvalidProofReceipt(#[from] ZkVmProofError),

    /// This error is returned when the output extraction process fails.
    #[error("Output extraction failed: {source}")]
    OutputExtractionError {
        /// The source of the failure, typically related to a data format issue.
        #[source]
        source: DataFormatError,
    },

    /// This error is returned when a proof is requested before it is ready.
    #[error("Proof is not ready")]
    ProofNotReady,

    /// A general catch-all variant for errors not covered by the other variants.
    #[error("{0}")]
    Other(String),
}

impl ZkVmError {
    /// Returns `true` if retrying the same request cannot succeed.
    ///
    /// See [`ZkVmError`] for the rule.
    pub fn is_permanent(&self) -> bool {
        match self {
            Self::ExecutionError(err) => err.is_permanent(),
            Self::InvalidInput(_)
            | Self::InvalidELF(_)
            | Self::InvalidVerifyingKey(_)
            | Self::InvalidProofReceipt(_)
            | Self::ProofVerificationError(_)
            | Self::OutputExtractionError { .. } => true,
            // Mostly prover faults. Adapters report the guest faults they can
            // spot as a guest `ExecutionError` instead.
            Self::ProofGenerationError(_) => false,
            Self::NetworkRetryableError(_) | Self::ProofNotReady | Self::Other(_) => false,
        }
    }
}

/// Why a program's execution failed.
///
/// The split tells callers whether retrying can help. A guest failure is a
/// property of the program and its input, so it repeats on every run. A host
/// failure comes from the machine running the executor, so a later run may
/// succeed.
#[derive(Debug, Error)]
pub enum ZkVmExecutionError {
    /// The guest program failed, e.g. it panicked or hit an invalid
    /// instruction. Retrying the same input fails the same way.
    #[error("guest error: {0}")]
    Guest(String),

    /// The host could not run the guest to completion, e.g. the executor
    /// process crashed or ran out of resources. Retrying may succeed.
    #[error("host error: {0}")]
    Host(String),
}

impl ZkVmExecutionError {
    /// Returns `true` for a guest failure. See [`ZkVmError`] for the rule.
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Guest(_))
    }
}

/// Errors related to data formatting and serialization/deserialization.
#[derive(Debug, Error)]
pub enum DataFormatError {
    /// An error occurred during borsh (de)serialization.
    #[cfg(feature = "borsh")]
    #[error("{source}")]
    Borsh {
        /// The source borsh error.
        #[source]
        source: BorshIoError,
    },

    /// An error occurred during Serde (de)serialization.
    #[error("{0}")]
    Serde(String),

    /// An error occurred during SSZ (de)serialization.
    #[cfg(feature = "ssz")]
    #[error("{source}")]
    Ssz {
        /// The source SSZ decode error.
        #[source]
        source: ssz::DecodeError,
    },

    /// A catch-all for other data format errors.
    #[error("error: {0}")]
    Other(String),
}

/// Errors related to ZkVM input validation.
#[derive(Debug, Error)]
pub enum ZkVmInputError {
    /// An input data format issue occurred.
    #[error("Input data format error: {0}")]
    DataFormat(#[source] DataFormatError),

    /// An input proof receipt issue occurred.
    #[error("Input proof receipt error: {0}")]
    ProofReceipt(#[source] ZkVmProofError),

    /// An input verification key issue occurred.
    #[error("Input verification key error: {0}")]
    VerifyingKey(#[source] ZkVmVerifyingKeyError),

    /// An input build process error occurred.
    #[error("Input build error: {0}")]
    InputBuild(String),
}

/// Errors related to verification key usage or parsing in ZkVM.
#[derive(Debug, Error)]
pub enum ZkVmVerifyingKeyError {
    /// An error occurred due to a verification key data format issue.
    #[error("Verification key format error: {0}")]
    DataFormat(#[source] DataFormatError),

    /// The provided verification key is of an invalid size.
    #[error("Verification key size error")]
    InvalidVerifyingKeySize,
}

/// A generic “expected vs actual” error.
#[derive(Debug, Error)]
#[error("expected {expected}, found {actual}")]
pub struct Mismatched<T>
where
    T: Debug + Display,
{
    /// The value that was expected.
    pub expected: T,
    /// The value that was actually encountered.
    pub actual: T,
}

/// Errors related to proof usage in ZkVM.
#[derive(Debug, Error)]
pub enum ZkVmProofError {
    /// An error occurred due to a proof data format issue.
    #[error("Proof data format error: {0}")]
    DataFormat(#[source] DataFormatError),

    /// The proof type provided does not match the expected proof type.
    #[error("Invalid ProofType: expected {0:?}")]
    InvalidProofType(ProofType),

    /// The ZkVM instance provided does not match the expected one.
    #[error(transparent)]
    ZkVmMismatch(#[from] Mismatched<ZkVm>),

    /// The ZkVM version provided does not match the expected one.
    #[error(transparent)]
    VersionMismatch(#[from] Mismatched<String>),
}

/// Errors that can occur when attempting to parse or handle a verification key.
#[derive(Debug, Error)]
pub enum InvalidVerifyingKeySource {
    /// A verification key data format issue occurred.
    #[error("Verification key format error: {0}")]
    DataFormat(#[from] DataFormatError),
}

/// Implement automatic conversion for `borsh::io::Error` to `DataFormatError`
#[cfg(feature = "borsh")]
impl From<BorshIoError> for DataFormatError {
    fn from(err: BorshIoError) -> Self {
        DataFormatError::Borsh { source: err }
    }
}

/// Implement automatic conversion for `borsh::io::Error` to `InvalidProofReceiptSource`
#[cfg(feature = "borsh")]
impl From<BorshIoError> for ZkVmProofError {
    fn from(err: BorshIoError) -> Self {
        let source = DataFormatError::Borsh { source: err };
        ZkVmProofError::DataFormat(source)
    }
}

/// Implement automatic conversion for `borsh::io::Error` to `ZkVmInputError`
#[cfg(feature = "borsh")]
impl From<BorshIoError> for ZkVmInputError {
    fn from(err: BorshIoError) -> Self {
        let source = DataFormatError::Borsh { source: err };
        ZkVmInputError::DataFormat(source)
    }
}

/// Implement automatic conversion for `ssz::DecodeError` to `DataFormatError`
#[cfg(feature = "ssz")]
impl From<ssz::DecodeError> for DataFormatError {
    fn from(err: ssz::DecodeError) -> Self {
        DataFormatError::Ssz { source: err }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_faults_are_permanent() {
        let permanent = [
            ZkVmExecutionError::Guest("panic".into()).into(),
            ZkVmError::InvalidELF("bad elf".into()),
            ZkVmError::InvalidVerifyingKey(ZkVmVerifyingKeyError::InvalidVerifyingKeySize),
            ZkVmError::InvalidProofReceipt(ZkVmProofError::InvalidProofType(ProofType::Core)),
            ZkVmError::ProofVerificationError("bad proof".into()),
        ];
        for err in permanent {
            assert!(err.is_permanent(), "{err:?} must be permanent");
        }
    }

    #[test]
    fn environment_faults_are_transient() {
        let transient = [
            ZkVmExecutionError::Host("SIGBUS".into()).into(),
            ZkVmError::NetworkRetryableError("503".into()),
            ZkVmError::ProofGenerationError("out of memory".into()),
            ZkVmError::ProofNotReady,
            ZkVmError::Other("???".into()),
        ];
        for err in transient {
            assert!(!err.is_permanent(), "{err:?} must be transient");
        }
    }
}
