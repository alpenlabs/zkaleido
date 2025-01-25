use std::fmt;

use hex::encode;
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, sha::Digest, Journal, ProverOpts,
};
use serde::{de::DeserializeOwned, Serialize};
use strata_zkvm::{
    ProofType, PublicValues, VerificationKey, ZkVmError, ZkVmHost, ZkVmInputBuilder, ZkVmResult,
};

use crate::{input::Risc0ProofInputBuilder, proof::Risc0ProofReceipt};

/// A host for the `Risc0` zkVM that stores the guest program in ELF format
/// The `Risc0Host` is responsible for program execution and proving
#[derive(Clone)]
pub struct Risc0Host {
    elf: Vec<u8>,
    id: Digest,
}

impl Risc0Host {
    pub fn init(guest_code: &[u8]) -> Self {
        let id = compute_image_id(guest_code).expect("invalid elf");
        Risc0Host {
            elf: guest_code.to_vec(),
            id,
        }
    }
}

impl ZkVmHost for Risc0Host {
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

    fn extract_serde_public_output<T: Serialize + DeserializeOwned>(
        proof: &PublicValues,
    ) -> ZkVmResult<T> {
        let journal = Journal::new(proof.as_bytes().to_vec());
        journal
            .decode()
            .map_err(|e| ZkVmError::OutputExtractionError {
                source: strata_zkvm::DataFormatError::Serde(e.to_string()),
            })
    }

    fn get_elf(&self) -> &[u8] {
        &self.elf
    }

    fn get_verification_key(&self) -> VerificationKey {
        VerificationKey::new(self.id.as_bytes().to_vec())
    }

    fn verify_inner(&self, proof: &Risc0ProofReceipt) -> ZkVmResult<()> {
        proof
            .as_ref()
            .verify(self.id)
            .map_err(|e| ZkVmError::ProofVerificationError(e.to_string()))?;
        Ok(())
    }
}

impl fmt::Debug for Risc0Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "risc0_{}", encode(self.id.as_bytes()))
    }
}
