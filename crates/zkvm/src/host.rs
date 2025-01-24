use std::fmt::Debug;

use borsh::BorshDeserialize;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    input::ZkVmInputBuilder, ProofReceipt, ProofType, PublicValues, VerificationKey, ZkVmError,
    ZkVmProofError, ZkVmResult,
};

/// A trait implemented by the prover ("host") of a zkVM program.
pub trait ZkVmHost: Send + Sync + Clone + Debug + 'static {
    type Input<'a>: ZkVmInputBuilder<'a>;

    type ZkVmProofReceipt: TryInto<ProofReceipt, Error = ZkVmProofError>
        + TryFrom<ProofReceipt, Error = ZkVmProofError>;

    /// Executes the guest code within the VM, generating and returning ZkVm specific validity
    /// proof.
    fn prove_inner<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<Self::ZkVmProofReceipt>;

    /// Executes the guest code within the VM, generating and returning [`ProofReceipt`].
    fn prove<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<ProofReceipt> {
        let receipt = self.prove_inner(input, proof_type)?;
        receipt.try_into().map_err(ZkVmError::InvalidProofReceipt)
    }

    /// Executes the guest code within the VM, generating and returning [`ProofReceipt`].
    fn execute<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
    ) -> ZkVmResult<(PublicValues, u64)>;

    /// Returns the Verification key for the loaded program
    fn get_verification_key(&self) -> VerificationKey;

    /// Returns the ELF for the loaded program
    fn get_elf(&self) -> &[u8];

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

    /// Verifies the proof generated by the ZkVm
    fn verify_inner(&self, proof: &Self::ZkVmProofReceipt) -> ZkVmResult<()>;

    /// Verifies the [`ProofReceipt`]
    fn verify(&self, proof: &ProofReceipt) -> ZkVmResult<()> {
        self.verify_inner(&proof.clone().try_into()?)
    }
}
