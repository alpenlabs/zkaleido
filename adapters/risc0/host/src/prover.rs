use risc0_zkvm::{default_executor, default_prover, ProverOpts};
use zkaleido::{
    ProofType, PublicValues, ZkVmError, ZkVmExecutor, ZkVmInputBuilder, ZkVmProver, ZkVmResult,
};

use crate::{input::Risc0ProofInputBuilder, proof::Risc0ProofReceipt, Risc0Host};

impl ZkVmExecutor for Risc0Host {
    type Input<'a> = Risc0ProofInputBuilder<'a>;

    fn execute<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
    ) -> ZkVmResult<PublicValues> {
        let executor = default_executor();

        let session_info = executor
            .execute(prover_input, self.get_elf())
            .map_err(|e| ZkVmError::ExecutionError(e.to_string()))?;

        let public_values = PublicValues::new(session_info.journal.bytes);
        Ok(public_values)
    }

    fn get_elf(&self) -> &[u8] {
        self.elf()
    }

    fn save_trace(&self, trace_name: &str) {
        let profiling_file_name = format!("{}_{:?}.trace_profile", trace_name, self);
        std::env::set_var("RISC0_PPROF_OUT", profiling_file_name);
    }
}

impl ZkVmProver for Risc0Host {
    type ZkVmProofReceipt = Risc0ProofReceipt;

    fn prove_inner<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<Risc0ProofReceipt> {
        // If the environment variable "ZKVM_MOCK" is set to "1" or "true" (case-insensitive),
        // then enable "RISC0_DEV_MODE" . This effectively enables the mock mode in the Risc0
        // prover.
        if std::env::var("ZKVM_MOCK")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
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
            .prove_with_opts(prover_input, self.get_elf(), &opts)
            .map_err(|e| ZkVmError::ProofGenerationError(e.to_string()))?;

        Ok(proof_info.receipt.into())
    }
}
