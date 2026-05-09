use std::{
    env::{set_var, var},
    future::Future,
    time::Duration,
};

use sp1_sdk::{
    HashableKey, ProvingKey, SP1ProofWithPublicValues,
    blocking::{CpuProver, MockProver, ProveRequest, Prover, ProverClient},
};
use tokio::{
    runtime::{Handle, Runtime},
    task::block_in_place,
    time::sleep,
};
use zkaleido::{
    ExecutionSummary, ProgramId, ProofType, PublicValues, RemoteProofStatus, ZkVmError,
    ZkVmExecutor, ZkVmInputBuilder, ZkVmProver, ZkVmRemoteProver, ZkVmResult,
};

use crate::{SP1Host, input::SP1ProofInputBuilder, proof::SP1ProofReceipt};

const NETWORK_POLL_INTERVAL: Duration = Duration::from_secs(10);

impl ZkVmExecutor for SP1Host {
    type Input<'a> = SP1ProofInputBuilder;
    fn execute<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
    ) -> ZkVmResult<ExecutionSummary> {
        let client = ProverClient::builder().light().build();
        let elf = self.proving_key.elf().clone();
        let (output, report) = client
            .execute(elf, prover_input)
            .run()
            .map_err(|e| ZkVmError::ExecutionError(e.to_string()))?;

        let public_values = PublicValues::new(output.to_vec());

        Ok(ExecutionSummary::new(
            public_values,
            report.total_instruction_count(),
            report.gas(),
        ))
    }

    fn get_elf(&self) -> &[u8] {
        self.proving_key.elf()
    }

    fn save_trace(&self, trace_name: &str) {
        let profiling_file_name = format!("{}_{:?}.trace_profile", trace_name, &self);
        // SAFETY: SP1 consumes this process-global trace setting from the
        // environment. Callers must configure tracing before concurrent prover
        // work starts.
        unsafe {
            set_var("TRACE_FILE", profiling_file_name);
        }
    }

    fn program_id(&self) -> ProgramId {
        ProgramId(self.proving_key.verifying_key().bytes32_raw())
    }
}

impl ZkVmProver for SP1Host {
    type ZkVmProofReceipt = SP1ProofReceipt;
    fn prove_inner<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<SP1ProofReceipt> {
        if is_network_prover() {
            return block_on_async(self.prove_via_network(prover_input, proof_type));
        }

        let proof_info = if use_mock_prover() {
            let client = ProverClient::builder().mock().build();
            run_prove_request::<MockProver>(
                client.prove(&self.proving_key, prover_input),
                proof_type,
            )
            .map_err(|e| ZkVmError::ProofGenerationError(e.to_string()))?
        } else {
            let client = ProverClient::builder().cpu().build();
            run_prove_request::<CpuProver>(
                client.prove(&self.proving_key, prover_input),
                proof_type,
            )
            .map_err(|e| ZkVmError::ProofGenerationError(e.to_string()))?
        };

        Ok(SP1ProofReceipt::new(proof_info, self.program_id()))
    }
}

impl SP1Host {
    /// Drives the async [`ZkVmRemoteProver`] methods (`start_proving` →
    /// poll `get_status` → `get_proof`) to produce an [`SP1ProofReceipt`].
    ///
    /// Used as the synchronous network proving path so that callers can invoke
    /// [`ZkVmProver::prove`] without choosing between the SP1 SDK's `blocking`
    /// API (which panics inside an existing tokio runtime) and the async API
    /// (which requires propagating `async` through every caller).
    async fn prove_via_network<'a>(
        &self,
        input: <<Self as ZkVmExecutor>::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<SP1ProofReceipt> {
        let id = self.start_proving(input, proof_type).await?;
        loop {
            match self.get_status(&id).await? {
                RemoteProofStatus::Completed => break,
                RemoteProofStatus::Failed(reason) => {
                    return Err(ZkVmError::ProofGenerationError(reason));
                }
                RemoteProofStatus::Requested
                | RemoteProofStatus::InProgress
                | RemoteProofStatus::Unknown => {
                    sleep(NETWORK_POLL_INTERVAL).await;
                }
            }
        }
        let receipt_with_metadata = self.get_proof(&id).await?;
        SP1ProofReceipt::try_from(receipt_with_metadata).map_err(ZkVmError::InvalidProofReceipt)
    }
}

fn run_prove_request<'a, P>(
    request: P::ProveRequest<'a>,
    proof_type: ProofType,
) -> Result<SP1ProofWithPublicValues, P::Error>
where
    P: Prover + 'a,
{
    match proof_type {
        ProofType::Compressed => request.compressed().run(),
        ProofType::Core => request.core().run(),
        ProofType::Groth16 => request.groth16().run(),
    }
}

fn is_network_prover() -> bool {
    !use_zkvm_mock() && var("SP1_PROVER").map(|v| v == "network").unwrap_or(false)
}

fn use_mock_prover() -> bool {
    use_zkvm_mock() || var("SP1_PROVER").map(|v| v == "mock").unwrap_or(false)
}

fn use_zkvm_mock() -> bool {
    var("ZKVM_MOCK")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Drives `future` to completion from a synchronous context, regardless of
/// whether the caller is already inside a tokio runtime.
///
/// Inside an existing multi-thread runtime, uses
/// [`tokio::task::block_in_place`] + [`Handle::block_on`] to avoid the nested
/// runtime panic produced by the SP1 SDK's `blocking` feature. Outside any
/// runtime, builds a fresh [`Runtime`] for this call.
///
/// **Caveat:** `block_in_place` requires a multi-thread runtime. Callers
/// running `current_thread` tokio runtimes should invoke the
/// [`ZkVmRemoteProver`] methods directly instead of going through sync
/// [`ZkVmProver::prove`].
fn block_on_async<F>(future: F) -> F::Output
where
    F: Future,
{
    match Handle::try_current() {
        Ok(handle) => block_in_place(|| handle.block_on(future)),
        Err(_) => {
            let rt = Runtime::new().expect("failed to build tokio runtime for sp1 prove");
            rt.block_on(future)
        }
    }
}
