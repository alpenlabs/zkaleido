use zkaleido::{
    AggregationInput, DataFormatError, ProofReceiptWithMetadata, ZkVmInputBuilder, ZkVmInputError,
    ZkVmInputResult,
};

use crate::env::NativeMachine;

/// A thin wrapper around [`NativeMachine`] that implements input-building traits.
///
/// This newtype allows for seamless integration with components expecting a
/// [`ZkVmInputBuilder`]. It delegates serialization and other input preparation
/// tasks to the underlying [`NativeMachine`].
#[derive(Debug)]
pub struct NativeMachineInputBuilder(pub NativeMachine);

impl ZkVmInputBuilder<'_> for NativeMachineInputBuilder {
    type Input = NativeMachine;
    type ZkVmProofReceipt = ProofReceiptWithMetadata;

    fn new() -> NativeMachineInputBuilder {
        Self(NativeMachine::new())
    }

    fn write_buf(&mut self, item: &[u8]) -> ZkVmInputResult<&mut Self> {
        self.0.write_slice(item.to_vec());
        Ok(self)
    }

    fn write_serde<T: serde::Serialize>(&mut self, item: &T) -> ZkVmInputResult<&mut Self> {
        let slice = bincode::serialize(&item)
            .map_err(|e| ZkVmInputError::DataFormat(DataFormatError::Serde(e.to_string())))?;
        self.write_buf(&slice)
    }

    fn write_borsh<T: borsh::BorshSerialize>(&mut self, item: &T) -> ZkVmInputResult<&mut Self> {
        let slice = borsh::to_vec(item)?;
        self.write_buf(&slice)
    }

    #[cfg(feature = "ssz")]
    fn write_ssz<T: ssz::Encode>(&mut self, item: &T) -> ZkVmInputResult<&mut Self> {
        self.write_buf(&item.as_ssz_bytes())
    }

    fn write_proof(&mut self, item: &AggregationInput) -> ZkVmInputResult<&mut Self> {
        // For the native mode we only write the public values since the proof is expected to be
        // empty
        self.write_buf(item.receipt().receipt().public_values().as_bytes())
    }

    fn build(&mut self) -> ZkVmInputResult<Self::Input> {
        Ok(self.0.clone())
    }
}
