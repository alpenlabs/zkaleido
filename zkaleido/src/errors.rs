use thiserror::Error;

use crate::{ProofType, ZkVm};

/// A convenient alias for results in the ZkVM.
pub type ZkVmResult<T> = Result<T, ZkVmError>;

/// General ZkVM error types.
#[derive(Debug, Error)]
pub enum ZkVmError {
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
    /// It wraps the underlying [`ZkVmVerificationKeyError`].
    #[error("Invalid Verification Key")]
    InvalidVerificationKey(#[from] ZkVmVerificationKeyError),

    /// This error occurs if the proof receipt is invalid.
    /// It wraps the underlying [`ZkVmProofError`].
    #[error("Invalid proof receipt")]
    InvalidProofReceipt(#[from] ZkVmProofError),

    /// This error is returned when the output extraction process fails.
    #[error("Output extraction failed")]
    OutputExtractionError {
        /// The source of the failure, typically related to a data format issue.
        #[source]
        source: DataFormatError,
    },

    /// A general catch-all variant for errors not covered by the other variants.
    #[error("{0}")]
    Other(String),
}

/// Errors related to data formatting and serialization/deserialization.
#[derive(Debug, Error)]
pub enum DataFormatError {
    /// An error occurred during bincode (de)serialization.
    #[error("{source}")]
    Bincode {
        /// The source bincode error.
        #[source]
        source: bincode::Error,
    },

    /// An error occurred during borsh (de)serialization.
    #[error("{source}")]
    Borsh {
        /// The source borsh error.
        #[source]
        source: borsh::io::Error,
    },

    /// An error occurred during Serde (de)serialization.
    #[error("{0}")]
    Serde(String),

    /// A catch-all for other data format errors.
    #[error("error: {0}")]
    Other(String),
}

/// Errors related to ZkVM input validation.
#[derive(Debug, Error)]
pub enum ZkVmInputError {
    /// An input data format issue occurred.
    #[error("Input data format error")]
    DataFormat(#[source] DataFormatError),

    /// An input proof receipt issue occurred.
    #[error("Input proof receipt error")]
    ProofReceipt(#[source] ZkVmProofError),

    /// An input verification key issue occurred.
    #[error("Input verification key error")]
    VerificationKey(#[source] ZkVmVerificationKeyError),

    /// An input build process error occurred.
    #[error("Input build error: {0}")]
    InputBuild(String),
}

/// Errors related to verification key usage or parsing in ZkVM.
#[derive(Debug, Error)]
pub enum ZkVmVerificationKeyError {
    /// An error occurred due to a verification key data format issue.
    #[error("Verification Key format error")]
    DataFormat(#[source] DataFormatError),

    /// The provided verification key is of an invalid size.
    #[error("Verification Key size error")]
    InvalidVerificationKeySize,
}

/// Errors related to proof usage in ZkVM.
#[derive(Debug, Error)]
pub enum ZkVmProofError {
    /// An error occurred due to a proof data format issue.
    #[error("Input data format error")]
    DataFormat(#[source] DataFormatError),

    /// The proof type provided does not match the expected proof type.
    #[error("Invalid ProofType: expected {0:?}")]
    InvalidProofType(ProofType),

    /// The ZkVM instance provided does not match the expected one.
    #[error("Invalid ZkVm: expected {0:?}, found {1:?}")]
    InvalidZkVm(ZkVm, ZkVm),
}

/// Errors that can occur when attempting to parse or handle a verification key.
#[derive(Debug, Error)]
pub enum InvalidVerificationKeySource {
    /// A verification key data format issue occurred.
    #[error("Verification Key format error")]
    DataFormat(#[from] DataFormatError),
}

/// Implement automatic conversion for `bincode::Error` to `DataFormatError`
impl From<bincode::Error> for DataFormatError {
    fn from(err: bincode::Error) -> Self {
        DataFormatError::Bincode { source: err }
    }
}

/// Implement automatic conversion for `borsh::io::Error` to `DataFormatError`
impl From<borsh::io::Error> for DataFormatError {
    fn from(err: borsh::io::Error) -> Self {
        DataFormatError::Borsh { source: err }
    }
}

/// Implement automatic conversion for `bincode::Error` to `InvalidProofReceipt`
impl From<bincode::Error> for ZkVmProofError {
    fn from(err: bincode::Error) -> Self {
        let source = DataFormatError::Bincode { source: err };
        ZkVmProofError::DataFormat(source)
    }
}

/// Implement automatic conversion for `borsh::io::Error` to `InvalidProofReceiptSource`
impl From<borsh::io::Error> for ZkVmProofError {
    fn from(err: borsh::io::Error) -> Self {
        let source = DataFormatError::Borsh { source: err };
        ZkVmProofError::DataFormat(source)
    }
}

/// Implement automatic conversion for `bincode::Error` to `ZkVmInputError`
impl From<bincode::Error> for ZkVmInputError {
    fn from(err: bincode::Error) -> Self {
        let source = DataFormatError::Bincode { source: err };
        ZkVmInputError::DataFormat(source)
    }
}

/// Implement automatic conversion for `borsh::io::Error` to `ZkVmInputError`
impl From<borsh::io::Error> for ZkVmInputError {
    fn from(err: borsh::io::Error) -> Self {
        let source = DataFormatError::Borsh { source: err };
        ZkVmInputError::DataFormat(source)
    }
}
