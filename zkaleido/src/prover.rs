use std::fmt::{Debug, Display};

use async_trait::async_trait;

use crate::{
    input::ZkVmInputBuilder, ExecutionSummary, ProofReceiptWithMetadata, ProofType, ZkVmError,
    ZkVmProofError, ZkVmResult,
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

/// Status of a remote proof request.
///
/// Modeled after SP1's `FulfillmentStatus` but simplified to be backend-agnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteProofStatus {
    /// The proof request has been submitted but work has not started.
    Requested,
    /// The proof is actively being generated.
    InProgress,
    /// The proof has been generated and is ready for retrieval.
    Completed,
    /// The proof generation failed.
    Failed(String),
    /// The status could not be determined.
    Unknown,
}

/// A trait implemented by the prover of a zkVM program.
///
/// This trait extends [`ZkVmProver`] to support asynchronous remote proving operations.
/// It provides methods to start the proving process, check its status, and retrieve
/// the proof once it becomes available. Implementers of this trait typically handle
/// the remote communication required to generate and fetch proofs.
#[async_trait(?Send)]
pub trait ZkVmRemoteProver: ZkVmProver {
    /// A typed proof identifier returned by [`start_proving`](Self::start_proving).
    ///
    /// Must be displayable for logging and cloneable for repeated status queries.
    type ProofId: Debug + Display + Clone + 'static;

    /// Starts the proving process for the given input and proof type.
    ///
    /// This method initiates the remote proof generation and returns a typed
    /// proof identifier that can be used to query the status and retrieve
    /// the proof later.
    async fn start_proving<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<Self::ProofId>;

    /// Checks the status of a remote proof request.
    async fn get_status(&self, id: &Self::ProofId) -> ZkVmResult<RemoteProofStatus>;

    /// Retrieves the completed proof as a [`ProofReceiptWithMetadata`].
    ///
    /// Returns an error if the proof is not ready. Callers should check
    /// [`get_status`](Self::get_status) first.
    async fn get_proof(&self, id: &Self::ProofId) -> ZkVmResult<ProofReceiptWithMetadata>;
}
