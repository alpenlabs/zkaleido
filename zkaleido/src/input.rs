use crate::{AggregationInput, ProofReceiptWithMetadata, ZkVmInputError};

/// A convenient alias for results in the ZkVM.
pub type ZkVmInputResult<T> = Result<T, ZkVmInputError>;

/// A trait for managing inputs to a ZkVm prover. This trait provides methods for
/// adding inputs in various formats to be used during the proof generation process.
pub trait ZkVmInputBuilder<'a> {
    /// The data type representing the fully constructed set of inputs
    /// ready to be used by the ZkVM.
    type Input;

    /// The type of proof receipt that this builder can handle, typically convertible
    /// from a generic [`ProofReceipt`].
    type ZkVmProofReceipt: TryFrom<ProofReceiptWithMetadata>;

    /// Creates a new instance of the `ProverInputs` struct.
    fn new() -> Self;

    /// Serializes the given item using Serde and appends it to the list of inputs.
    fn write_serde<T: serde::Serialize>(&mut self, item: &T) -> ZkVmInputResult<&mut Self>;

    /// Serializes the given item using the Borsh serialization format and appends
    /// it to the list of inputs.
    fn write_borsh<T: borsh::BorshSerialize>(&mut self, item: &T) -> ZkVmInputResult<&mut Self>;

    /// Appends a pre-serialized byte array to the list of inputs.
    ///
    /// This method is intended for cases where the data has already been serialized
    /// outside of the zkVM's standard serialization methods. It allows you to provide
    /// serialized inputs directly, bypassing any further serialization.
    fn write_buf(&mut self, item: &[u8]) -> ZkVmInputResult<&mut Self>;

    /// Adds an `AggregationInput` to the list of aggregation/composition inputs.
    ///
    /// This method is specifically used for cases where proof aggregation or composition
    /// is involved, allowing for proof and verification inputs to be provided to the zkVM.
    fn write_proof(&mut self, item: &AggregationInput) -> ZkVmInputResult<&mut Self>;

    /// Finalizes and returns the constructed `Input` data structure.
    fn build(&mut self) -> ZkVmInputResult<Self::Input>;
}
