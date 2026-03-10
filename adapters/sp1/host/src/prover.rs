#[cfg(feature = "remote-prover")]
use sp1_sdk::{
    network::{
        proto::types::{ExecutionStatus, FulfillmentStatus},
        B256,
    },
    SP1ProofMode,
};
use sp1_sdk::{
    network::{Error as NetworkError, FulfillmentStrategy},
    ProverClient,
};
#[cfg(feature = "remote-prover")]
use zkaleido::{ProofReceiptWithMetadata, RemoteProofStatus, ZkVmRemoteProver};
use zkaleido::{
    ExecutionSummary, ProofType, PublicValues, ZkVmError, ZkVmExecutor, ZkVmInputBuilder,
    ZkVmProver, ZkVmResult,
};

use crate::{input::SP1ProofInputBuilder, proof::SP1ProofReceipt, SP1Host};

impl ZkVmExecutor for SP1Host {
    type Input<'a> = SP1ProofInputBuilder;
    fn execute<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
    ) -> ZkVmResult<ExecutionSummary> {
        let client = ProverClient::from_env();

        let (output, report) = client
            .execute(self.get_elf(), &prover_input)
            .run()
            .map_err(|e| ZkVmError::ExecutionError(e.to_string()))?;

        let public_values = PublicValues::new(output.to_vec());

        Ok(ExecutionSummary::new(
            public_values,
            report.total_instruction_count(),
            report.gas,
        ))
    }

    fn get_elf(&self) -> &[u8] {
        &self.proving_key.elf
    }

    fn save_trace(&self, trace_name: &str) {
        let profiling_file_name = format!("{}_{:?}.trace_profile", trace_name, &self);
        std::env::set_var("TRACE_FILE", profiling_file_name);
    }
}

impl ZkVmProver for SP1Host {
    type ZkVmProofReceipt = SP1ProofReceipt;
    fn prove_inner<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<SP1ProofReceipt> {
        // If the environment variable "ZKVM_MOCK" is set to "1" or "true" (case-insensitive),
        // then set "SP1_PROVER" to "mock". This effectively enables the mock mode in the SP1
        // prover.
        if std::env::var("ZKVM_MOCK")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            std::env::set_var("SP1_PROVER", "mock");
        }

        let is_network_prover = std::env::var("SP1_PROVER")
            .map(|v| v == "network")
            .unwrap_or(false);

        if is_network_prover {
            let prover_client = ProverClient::builder().network().build();
            let strategy = std::env::var("SP1_PROOF_STRATEGY")
                .ok()
                .and_then(|s| FulfillmentStrategy::from_str_name(&s.to_ascii_uppercase()))
                .unwrap_or(FulfillmentStrategy::Auction);

            let network_prover_builder = prover_client
                .prove(&self.proving_key, &prover_input)
                .strategy(strategy);

            let network_prover = match proof_type {
                ProofType::Compressed => network_prover_builder.compressed(),
                ProofType::Core => network_prover_builder.core(),
                ProofType::Groth16 => network_prover_builder.groth16(),
            };

            let proof_result = network_prover.run();

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

            return Ok(proof.into());
        }

        let client = ProverClient::from_env();
        let mut prover = client.prove(&self.proving_key, &prover_input);

        prover = match proof_type {
            ProofType::Compressed => prover.compressed(),
            ProofType::Core => prover.core(),
            ProofType::Groth16 => prover.groth16(),
        };

        let proof_info = prover
            .run()
            .map_err(|e| ZkVmError::ProofGenerationError(e.to_string()))?;

        Ok(proof_info.into())
    }
}

/// A typed proof identifier for the SP1 network prover.
#[cfg(feature = "remote-prover")]
#[derive(Debug, Clone)]
pub struct Sp1ProofId(B256);

#[cfg(feature = "remote-prover")]
impl std::fmt::Display for Sp1ProofId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0 .0))
    }
}

#[cfg(feature = "remote-prover")]
#[async_trait::async_trait(?Send)]
impl ZkVmRemoteProver for SP1Host {
    type ProofId = Sp1ProofId;

    async fn start_proving<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<Sp1ProofId> {
        let client = ProverClient::builder().network().build();

        let strategy = std::env::var("SP1_PROOF_STRATEGY")
            .ok()
            .and_then(|s| FulfillmentStrategy::from_str_name(&s.to_ascii_uppercase()))
            .unwrap_or(FulfillmentStrategy::Auction);

        let mode = match proof_type {
            ProofType::Core => SP1ProofMode::Core,
            ProofType::Compressed => SP1ProofMode::Compressed,
            ProofType::Groth16 => SP1ProofMode::Groth16,
        };

        let pk = &self.proving_key;
        let request_id = client
            .prove(pk, &input)
            .strategy(strategy)
            .mode(mode)
            .request_async()
            .await
            .map_err(|e| ZkVmError::ProofGenerationError(e.to_string()))?;

        Ok(Sp1ProofId(request_id))
    }

    async fn get_status(&self, id: &Sp1ProofId) -> ZkVmResult<RemoteProofStatus> {
        let client = ProverClient::builder().network().build();
        let (status, _) = client
            .get_proof_status(id.0)
            .await
            .map_err(|e| ZkVmError::NetworkRetryableError(e.to_string()))?;

        let execution_status = ExecutionStatus::try_from(status.execution_status)
            .unwrap_or(ExecutionStatus::UnspecifiedExecutionStatus);

        if execution_status == ExecutionStatus::Unexecutable {
            return Ok(RemoteProofStatus::Failed("unexecutable".to_string()));
        }

        let fulfillment_status = FulfillmentStatus::try_from(status.fulfillment_status)
            .unwrap_or(FulfillmentStatus::UnspecifiedFulfillmentStatus);

        let status = match fulfillment_status {
            FulfillmentStatus::Requested => RemoteProofStatus::Requested,
            FulfillmentStatus::Assigned => RemoteProofStatus::InProgress,
            FulfillmentStatus::Fulfilled => RemoteProofStatus::Completed,
            FulfillmentStatus::Unfulfillable => {
                RemoteProofStatus::Failed("unfulfillable".to_string())
            }
            FulfillmentStatus::UnspecifiedFulfillmentStatus => RemoteProofStatus::Unknown,
        };

        Ok(status)
    }

    async fn get_proof(&self, id: &Sp1ProofId) -> ZkVmResult<ProofReceiptWithMetadata> {
        let client = ProverClient::builder().network().build();
        let (_, proof) = client
            .get_proof_status(id.0)
            .await
            .map_err(|e| ZkVmError::NetworkRetryableError(e.to_string()))?;

        match proof {
            Some(proof) => {
                let sp1_receipt: SP1ProofReceipt = proof.into();
                sp1_receipt
                    .try_into()
                    .map_err(ZkVmError::InvalidProofReceipt)
            }
            None => Err(ZkVmError::ProofNotReady),
        }
    }
}
