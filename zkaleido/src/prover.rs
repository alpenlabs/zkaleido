use std::fmt::Debug;

use async_trait::async_trait;

use crate::{
    input::ZkVmInputBuilder, ProofReceipt, ProofType, PublicValues, ZkVmError, ZkVmProofError,
    ZkVmResult,
};

/// A trait implemented by types that execute zkVM programs.
pub trait ZkVmExecutor: Send + Sync + Clone + Debug + 'static {
    /// The input type used by this host to build all data necessary for running the VM.
    type Input<'a>: ZkVmInputBuilder<'a>;

    /// Executes the guest code within the VM returning the `PublicValues`.
    fn execute<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
    ) -> ZkVmResult<PublicValues>;

    /// Returns the ELF for the loaded program
    fn get_elf(&self) -> &[u8];
}

/// A trait implemented by types that not only execute zkVM programs, but also produce proofs.
///
/// This trait extends [`ZkVmExecutor`] by providing additional functionality necessary for
/// generating proofs in a zero-knowledge context.
pub trait ZkVmProver: ZkVmExecutor {
    /// The proof receipt type, specific to this host, that can be
    /// converted to and from a generic [`ProofReceipt`].
    ///
    /// This allows flexibility for different proof systems or proof representations
    /// while still providing a way to convert back to a standard [`ProofReceipt`].
    type ZkVmProofReceipt: TryInto<ProofReceipt, Error = ZkVmProofError>;

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
}

/// A trait implemented by the prover of a zkVM program.
///
/// This trait extends [`ZkVmProver`] to support asynchronous remote proving operations.
/// It provides methods to start the proving process and retrieve the proof once it
/// becomes available. Implementers of this trait typically handle the remote communication
/// required to generate and fetch proofs.
#[async_trait(?Send)]
pub trait ZkVmRemoteProver: ZkVmProver {
    /// Starts the proving process for the given input and proof type.
    ///
    /// This method typically initiates the remote proof generation and returns
    /// a proof identifier (`proof_id`) that can be used to query the status
    /// of the proof later.
    async fn start_proving<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<String>;

    /// Retrieves the proof if it is ready.
    ///
    /// This method performs the underlying logic to check whether the proof
    /// has been generated and is available from the remote service. If it is
    /// not ready yet, `None` will be returned.
    async fn get_proof_if_ready_inner(
        &self,
        id: String,
    ) -> ZkVmResult<Option<Self::ZkVmProofReceipt>>;

    /// Retrieves the proof if it is ready and converts it into a [`ProofReceipt`].
    ///
    /// Internally calls [`get_proof_if_ready_inner`](Self::get_proof_if_ready_inner)
    /// to fetch the proof receipt and attempts to convert it into a
    /// [`ProofReceipt`]. If the proof is not ready, `None` is returned.
    async fn get_proof_if_ready(&self, id: String) -> ZkVmResult<Option<ProofReceipt>> {
        let receipt = self.get_proof_if_ready_inner(id).await?;
        let res = match receipt {
            Some(inner_receipt) => Some(inner_receipt.try_into()?),
            None => None,
        };
        Ok(res)
    }
}
