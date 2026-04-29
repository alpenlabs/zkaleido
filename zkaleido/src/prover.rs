use std::fmt::Debug;

use crate::{
    ExecutionSummary, ProgramId, ProofReceiptWithMetadata, ProofType, ZkVmError, ZkVmProofError,
    ZkVmResult, input::ZkVmInputBuilder,
};

/// A trait implemented by types that execute zkVM programs.
pub trait ZkVmExecutor: Send + Sync + Clone + Debug + 'static {
    /// The input type used by this host to build all data necessary for running the VM.
    type Input<'a>: ZkVmInputBuilder<'a>;

    /// Executes the guest code within the VM returning the `ExecutionResult`.
    ///
    /// The `ExecutionResult` contains the public values, cycle count, and optional gas usage.
    fn execute<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
    ) -> ZkVmResult<ExecutionSummary>;

    /// Returns the ELF for the loaded program
    fn get_elf(&self) -> &[u8];

    /// Returns the program identifier, derived deterministically from the ELF.
    fn program_id(&self) -> ProgramId;

    /// Save the generated trace
    fn save_trace(&self, trace_name: &str);
}

/// A trait implemented by types that not only execute zkVM programs, but also produce proofs.
///
/// This trait extends [`ZkVmExecutor`] by providing additional functionality necessary for
/// generating proofs in a zero-knowledge context.
pub trait ZkVmProver: ZkVmExecutor {
    /// The proof receipt type, specific to this host, that can be
    /// converted to and from a generic [`ProofReceiptWithMetadata`].
    ///
    /// This allows flexibility for different proof systems or proof representations
    /// while still providing a way to convert back to a standard [`ProofReceipt`].
    type ZkVmProofReceipt: TryInto<ProofReceiptWithMetadata, Error = ZkVmProofError>;

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
    ) -> ZkVmResult<ProofReceiptWithMetadata> {
        let receipt = self.prove_inner(input, proof_type)?;
        receipt.try_into().map_err(ZkVmError::InvalidProofReceipt)
    }
}
