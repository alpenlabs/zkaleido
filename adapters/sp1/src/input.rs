use borsh::BorshSerialize;
use serde::Serialize;
use sp1_sdk::{SP1Proof, SP1Stdin, SP1VerifyingKey};
use zkaleido::{
    AggregationInput, ProofType, ZkVmInputBuilder, ZkVmInputError, ZkVmInputResult, ZkVmProofError,
    ZkVmVerifyingKeyError,
};

use crate::proof::SP1ProofReceipt;

/// A proof input builder for the SP1 host environment.
///
/// This newtype wraps an internal `SP1Stdin` from the SP1 library,
/// providing the required functionality to manage and serialize input data so
/// it can be consumed by the SP1 proof executor. This structure is typically
/// created by higher-level code that coordinates proof generation.
#[derive(Debug)]
pub struct SP1ProofInputBuilder(SP1Stdin);

impl ZkVmInputBuilder<'_> for SP1ProofInputBuilder {
    type Input = SP1Stdin;
    type ZkVmProofReceipt = SP1ProofReceipt;

    fn new() -> SP1ProofInputBuilder {
        SP1ProofInputBuilder(SP1Stdin::new())
    }

    fn write_serde<T: Serialize>(&mut self, item: &T) -> ZkVmInputResult<&mut Self> {
        self.0.write(item);
        Ok(self)
    }

    fn write_borsh<T: BorshSerialize>(&mut self, item: &T) -> ZkVmInputResult<&mut Self> {
        let slice = borsh::to_vec(item).map_err(|e| ZkVmInputError::DataFormat(e.into()))?;
        self.write_buf(&slice)
    }

    fn write_buf(&mut self, item: &[u8]) -> ZkVmInputResult<&mut Self> {
        self.0.write_slice(item);
        Ok(self)
    }

    fn write_proof(&mut self, item: &AggregationInput) -> ZkVmInputResult<&mut Self> {
        let receipt: SP1ProofReceipt = item
            .receipt()
            .try_into()
            .map_err(ZkVmInputError::ProofReceipt)?;
        let vkey: SP1VerifyingKey = bincode::deserialize(item.vk().as_bytes())
            .map_err(|e| ZkVmVerifyingKeyError::DataFormat(e.into()))
            .map_err(ZkVmInputError::VerifyingKey)?;

        // Write the public values of the program that'll be proven inside zkVM.
        self.0
            .write_slice(receipt.as_ref().public_values.as_slice());

        // Write the proofs.
        //
        // Note: this data will not actually be read by the aggregation program, instead it will
        // be witnessed by the prover during the recursive aggregation process
        // inside SP1 itself.
        match receipt.inner().proof {
            SP1Proof::Compressed(compressed_proof) => {
                self.0.write_proof(*compressed_proof, vkey.vk);
            }
            _ => {
                return Err(ZkVmInputError::ProofReceipt(
                    ZkVmProofError::InvalidProofType(ProofType::Compressed),
                ))
            }
        }

        Ok(self)
    }

    fn build(&mut self) -> ZkVmInputResult<Self::Input> {
        Ok(self.0.clone())
    }
}
