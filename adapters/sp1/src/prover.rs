use sp1_sdk::{
    network::{FulfillmentStrategy, B256},
    ProverClient, SP1ProofMode,
};
use zkaleido::{
    ProofType, PublicValues, ZkVmError, ZkVmExecutor, ZkVmInputBuilder, ZkVmProver,
    ZkVmRemoteProver, ZkVmResult,
};

use crate::{input::SP1ProofInputBuilder, proof::SP1ProofReceipt, SP1Host};

impl ZkVmExecutor for SP1Host {
    type Input<'a> = SP1ProofInputBuilder;
    fn execute<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
    ) -> ZkVmResult<PublicValues> {
        let client = ProverClient::from_env();

        let (output, _) = client
            .execute(self.get_elf(), &prover_input)
            .run()
            .map_err(|e| ZkVmError::ExecutionError(e.to_string()))?;

        let public_values = PublicValues::new(output.to_vec());

        Ok(public_values)
    }

    fn get_elf(&self) -> &[u8] {
        &self.proving_key.elf
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

#[async_trait::async_trait(?Send)]
impl ZkVmRemoteProver for SP1Host {
    async fn start_proving<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<String> {
        let client = ProverClient::builder().network().build();

        let strategy = std::env::var("SP1_PROOF_STRATEGY")
            .ok()
            .and_then(|s| FulfillmentStrategy::from_str_name(&s.to_ascii_uppercase()))
            .unwrap_or(FulfillmentStrategy::Hosted);

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
            .unwrap();
        let id = hex::encode(request_id.0);
        Ok(id)
    }

    async fn get_proof_if_ready_inner(&self, id: String) -> ZkVmResult<Option<SP1ProofReceipt>> {
        let client = ProverClient::builder().network().build();
        let request_id = hex::decode(id).unwrap();
        let request_id = B256::from_slice(&request_id);
        let (_, proof) = client.get_proof_status(request_id).await.unwrap();
        match proof {
            Some(proof) => Ok(Some(proof.into())),
            None => Ok(None),
        }
    }
}
