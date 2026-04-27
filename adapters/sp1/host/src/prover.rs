use std::env::{set_var, var};

use sp1_sdk::{
    HashableKey, ProvingKey, SP1ProofWithPublicValues,
    blocking::{CpuProver, MockProver, NetworkProver, ProveRequest, Prover, ProverClient},
    network::{Error as NetworkError, FulfillmentStrategy},
};
use zkaleido::{
    ExecutionSummary, ProgramId, ProofType, PublicValues, ZkVmError, ZkVmExecutor,
    ZkVmInputBuilder, ZkVmProver, ZkVmResult,
};

use crate::{SP1Host, input::SP1ProofInputBuilder, proof::SP1ProofReceipt};

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
        let is_network_prover =
            !use_zkvm_mock() && var("SP1_PROVER").map(|v| v == "network").unwrap_or(false);

        if is_network_prover {
            let prover_client = ProverClient::builder().network().build();
            let strategy = var("SP1_PROOF_STRATEGY")
                .ok()
                .and_then(|s| FulfillmentStrategy::from_str_name(&s.to_ascii_uppercase()))
                .unwrap_or(FulfillmentStrategy::Auction);

            let mut network_prover_builder = prover_client
                .prove(&self.proving_key, prover_input)
                .strategy(strategy);
            if let Some(deadline) = self.deadline {
                network_prover_builder = network_prover_builder.timeout(deadline);
            }

            let proof_result =
                run_prove_request::<NetworkProver>(network_prover_builder, proof_type);

            // Some error handling.
            // If SP1 network prover returned Network RPC error - transform it to zkaleido
            // network error, so the users can handle it gracefully.
            // Otherwise, return a general error message wrapped in ProofGeneratedError.
            let proof = match proof_result {
                Ok(proof) => proof,
                Err(e) => match e.downcast_ref::<NetworkError>() {
                    Some(NetworkError::RpcError(status)) => {
                        return Err(ZkVmError::NetworkRetryableError(status.to_string()));
                    }
                    _ => return Err(ZkVmError::ProofGenerationError(e.to_string())),
                },
            };

            return Ok(SP1ProofReceipt::new(proof, self.program_id()));
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

fn use_mock_prover() -> bool {
    use_zkvm_mock() || var("SP1_PROVER").map(|v| v == "mock").unwrap_or(false)
}

fn use_zkvm_mock() -> bool {
    var("ZKVM_MOCK")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}
