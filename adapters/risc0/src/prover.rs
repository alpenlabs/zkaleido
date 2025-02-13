use risc0_zkvm::{default_executor, default_prover, ProverOpts};
use zkaleido::{
    ProofType, PublicValues, ZkVmError, ZkVmInputBuilder, ZkVmProver, ZkVmRemoteProver, ZkVmResult,
};

use crate::{input::Risc0ProofInputBuilder, proof::Risc0ProofReceipt, Risc0Host};

impl ZkVmProver for Risc0Host {
    type Input<'a> = Risc0ProofInputBuilder<'a>;
    type ZkVmProofReceipt = Risc0ProofReceipt;

    fn prove_inner<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<Risc0ProofReceipt> {
        #[cfg(feature = "mock")]
        {
            std::env::set_var("RISC0_DEV_MODE", "true");
        }

        // Setup the prover
        let opts = match proof_type {
            ProofType::Core => ProverOpts::default(),
            ProofType::Compressed => ProverOpts::succinct(),
            ProofType::Groth16 => ProverOpts::groth16(),
        };

        let prover = default_prover();

        // Generate the proof
        let proof_info = prover
            .prove_with_opts(prover_input, &self.elf, &opts)
            .map_err(|e| ZkVmError::ProofGenerationError(e.to_string()))?;

        Ok(proof_info.receipt.into())
    }

    fn execute<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
    ) -> ZkVmResult<(PublicValues, u64)> {
        let executor = default_executor();

        if std::env::var("ZKVM_PROFILING_DUMP")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            let profiling_file_name = format!("{:?}.trace_profile", self);
            std::env::set_var("RISC0_PPROF_OUT", profiling_file_name);
        }

        // TODO: handle error
        let session_info = executor.execute(prover_input, self.get_elf()).unwrap();

        let cycles = session_info.cycles();
        let public_values = PublicValues::new(session_info.journal.bytes);
        Ok((public_values, cycles))
    }

    fn get_elf(&self) -> &[u8] {
        &self.elf
    }
}

#[async_trait::async_trait(?Send)]
impl ZkVmRemoteProver for Risc0Host {
    async fn start_proving<'a>(
        &self,
        _input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        _proof_type: ProofType,
    ) -> ZkVmResult<String> {
        todo!()
    }

    async fn get_proof_if_ready_inner(&self, _id: String) -> ZkVmResult<Option<Risc0ProofReceipt>> {
        unimplemented!()
    }
}
