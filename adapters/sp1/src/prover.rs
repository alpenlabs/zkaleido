use sp1_sdk::{network::B256, ProverClient};
use zkaleido::{
    ProofType, PublicValues, ZkVmError, ZkVmInputBuilder, ZkVmProver, ZkVmRemoteProver, ZkVmResult,
};

use crate::{input::SP1ProofInputBuilder, proof::SP1ProofReceipt, SP1Host};

impl ZkVmProver for SP1Host {
    type Input<'a> = SP1ProofInputBuilder;
    type ZkVmProofReceipt = SP1ProofReceipt;
    fn prove_inner<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<SP1ProofReceipt> {
        #[cfg(feature = "mock")]
        {
            std::env::set_var("SP1_PROVER", "mock");
        }

        let client = ProverClient::from_env();

        // Start proving
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

    fn execute<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
    ) -> ZkVmResult<(PublicValues, u64)> {
        let client = ProverClient::from_env();

        if std::env::var("ZKVM_PROFILING_DUMP")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            let profiling_file_name = format!("{:?}.trace_profile", self);
            std::env::set_var("TRACE_FILE", profiling_file_name);
        }

        let (output, report) = client.execute(self.get_elf(), &prover_input).run().unwrap();

        // Remove the variable after execution to avoid duplication of trace generation in perf
        // report
        std::env::remove_var("TRACE_FILE");

        let public_values = PublicValues::new(output.to_vec());
        let total_cycles = report.total_instruction_count();

        Ok((public_values, total_cycles))
    }

    fn get_elf(&self) -> &[u8] {
        &self.proving_key.elf
    }
}

#[async_trait::async_trait(?Send)]
impl ZkVmRemoteProver for SP1Host {
    async fn start_proving<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        _proof_type: ProofType,
    ) -> ZkVmResult<String> {
        let client = ProverClient::builder().network().build();
        let pk = &self.proving_key;
        let request_id = client.prove(pk, &input).request_async().await.unwrap();
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
