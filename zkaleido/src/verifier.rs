use std::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    ProofReceipt, ProofReceiptWithMetadata, PublicValues, VerifyingKey, VerifyingKeyCommitment,
    ZkVmError, ZkVmProofError, ZkVmResult,
};

/// A trait implemented by verifiers that work with typed proof receipts.
///
/// This trait is for verifiers that require `ProofReceiptWithMetadata` as input
/// and convert it to their own specific proof receipt type before verification.
/// This allows different zkVM implementations to use their own internal proof
/// representations while maintaining compatibility with the generic interface.
pub trait ZkVmTypedVerifier: Send + Sync + Clone + Debug + 'static {
    /// The proof receipt type, specific to this host, that can be
    /// converted to and from a generic [`ProofReceiptWithMetadata`].
    ///
    /// This allows flexibility for different proof systems or proof representations
    /// while still providing a way to convert back to a standard [`ProofReceiptWithMetadata`].
    type ZkVmProofReceipt: TryFrom<ProofReceiptWithMetadata, Error = ZkVmProofError>;

    /// Verifies the proof using the verifier's specific proof receipt type.
    ///
    /// This method performs the actual verification logic using the converted
    /// proof receipt type specific to this verifier implementation.
    fn verify_inner(&self, receipt: &Self::ZkVmProofReceipt) -> ZkVmResult<()>;

    /// Verifies a [`ProofReceiptWithMetadata`] by converting it to the specific type.
    ///
    /// This method handles the conversion from [`ProofReceiptWithMetadata`] to the
    /// verifier's specific proof receipt type, then delegates to `verify_inner`.
    fn verify(&self, receipt: &ProofReceiptWithMetadata) -> ZkVmResult<()> {
        self.verify_inner(&receipt.clone().try_into()?)
    }
}

/// A trait implemented by verifiers that work directly with proof receipts.
///
/// This trait is for verifiers that can work directly with `ProofReceipt`
/// without requiring metadata or type conversion. This is typically used
/// for simpler verification scenarios or when the verifier doesn't need
/// additional metadata about the proof generation process.
pub trait ZkVmVerifier: Send + Sync + Clone + Debug + 'static {
    /// Verifies a `ProofReceipt` directly.
    ///
    /// This method performs verification on the proof receipt without any
    /// conversion or metadata processing.
    fn verify(&self, receipt: &ProofReceipt) -> ZkVmResult<()>;
}

/// A trait for providing verification keys for zkVM programs.
pub trait ZkVmVkProvider: Send + Sync + Clone + Debug + 'static {
    /// Returns the Verification key for the loaded program
    fn vk(&self) -> VerifyingKey;

    /// Returns the commitment of the verification key for the loaded program
    fn vk_commitment(&self) -> VerifyingKeyCommitment;
}

/// A trait providing metadata and utility functions for zkVM proof receipts public values.
pub trait ZkVmOutputExtractor: Send + Sync + Clone + Debug + 'static {
    /// Extracts the public output from the public values using ZkVm's `serde`
    /// serialization/deserialization.
    fn extract_serde_public_output<T: Serialize + DeserializeOwned>(
        public_values: &PublicValues,
    ) -> ZkVmResult<T>;

    /// Extracts the public output from the given proof assuming the data was serialized using
    /// Borsh.
    fn extract_borsh_public_output<T: BorshDeserialize>(
        public_values: &PublicValues,
    ) -> ZkVmResult<T> {
        borsh::from_slice(public_values.as_bytes())
            .map_err(|e| ZkVmError::OutputExtractionError { source: e.into() })
    }
}

/// A no-op verifier: its `verify` method does nothing and always returns success.
///
/// Use this when you want to bypass verification logic entirely. It performs
/// no cryptographic checks on the proof receipt.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct NoopVerifier;

impl ZkVmVerifier for NoopVerifier {
    fn verify(&self, _receipt: &ProofReceipt) -> ZkVmResult<()> {
        Ok(())
    }
}
