use std::fmt::Debug;

use crate::{
    input::ZkVmInputBuilder, ProofReceipt, ProofType, PublicValues, ZkVmError, ZkVmProofError,
    ZkVmResult,
};

/// A trait implemented by the prover ("host") of a zkVM program.
pub trait ZkVmProver: Send + Sync + Clone + Debug + 'static {
    /// The input type used by this host to build all data necessary for running the VM.
    type Input<'a>: ZkVmInputBuilder<'a>;

    /// The proof receipt type, specific to this host, that can be
    /// converted to and from a generic [`ProofReceipt`].
    ///
    /// This allows flexibility for different proof systems or proof representations
    /// while still providing a way to convert back to a standard [`ProofReceipt`].
    type ZkVmProofReceipt: TryInto<ProofReceipt, Error = ZkVmProofError>
        + TryFrom<ProofReceipt, Error = ZkVmProofError>;

    /// Executes the guest code within the VM.
    ///
    /// # Returns
    /// A tuple containing:
    /// * `PublicValues` - The public values generated during proof execution.
    /// * `u64` - The cycle count for the execution
    fn execute<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
    ) -> ZkVmResult<(PublicValues, u64)>;

    /// Executes the guest code within the VM, generating and returning ZkVm specific validity
    /// proof.
    fn prove_inner<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<Self::ZkVmProofReceipt>;

    /// A higher-level proof function that generates a proof by calling `prove_inner` and
    /// then converts the resulting receipt into a generic [`ProofReceipt`].
    fn prove<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<ProofReceipt> {
        let receipt = self.prove_inner(input, proof_type)?;
        receipt.try_into().map_err(ZkVmError::InvalidProofReceipt)
    }

    /// Returns the ELF for the loaded program
    fn get_elf(&self) -> &[u8];
}
