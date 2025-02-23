use sp1_sdk::{network::FulfillmentStrategy, ProverClient};
use zkaleido::{
    ProofType, PublicValues, ZkVmError, ZkVmExecutor, ZkVmInputBuilder, ZkVmProver, ZkVmResult,
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

        // Handle network proving with custom strategy
        if std::env::var("SP1_PROOF_STRATEGY").unwrap_or_default() == "private_cluster" {
            let prover_client = ProverClient::builder().network().build();

            let network_prover_builder = prover_client
                .prove(&self.proving_key, &prover_input)
                .strategy(FulfillmentStrategy::Reserved);

            let network_prover = match proof_type {
                ProofType::Compressed => network_prover_builder.compressed(),
                ProofType::Core => network_prover_builder.core(),
                ProofType::Groth16 => network_prover_builder.groth16(),
            };

            let proof_info = network_prover
                .run()
                .map_err(|e| ZkVmError::ProofGenerationError(e.to_string()))?;

            return Ok(proof_info.into());
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
