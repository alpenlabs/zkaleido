use std::fmt;

use serde::{de::DeserializeOwned, Serialize};
use sp1_sdk::{network::FulfillmentStrategy, HashableKey, ProverClient, SP1ProvingKey};
use zkaleido::{
    ProofType, PublicValues, VerificationKey, VerificationKeyCommitment, ZkVmError, ZkVmHost,
    ZkVmInputBuilder, ZkVmResult,
};

use crate::{input::SP1ProofInputBuilder, proof::SP1ProofReceipt};

/// A host for the `SP1` zkVM that stores the guest program in ELF format.
/// The `SP1Host` is responsible for program execution and proving
#[derive(Clone)]
pub struct SP1Host {
    /// Proving Key
    pub proving_key: SP1ProvingKey,
}

impl SP1Host {
    /// Creates a new instance of [`SP1Host`] using the provided [`SP1ProvingKey`].
    pub fn new(proving_key: SP1ProvingKey) -> Self {
        Self { proving_key }
    }

    /// Creates a new instance of [`SP1Host`] from serialized proving key bytes.
    pub fn new_from_bytes(proving_key_bytes: &[u8]) -> Self {
        let proving_key: SP1ProvingKey =
            bincode::deserialize(proving_key_bytes).expect("invalid sp1 pk bytes");
        SP1Host::new(proving_key)
    }

    /// Initializes a new [`SP1Host`] by setting up the proving key using the provided ELF bytes.
    pub fn init(elf: &[u8]) -> Self {
        let client = ProverClient::from_env();
        let (proving_key, _) = client.setup(elf);
        Self { proving_key }
    }
}

impl ZkVmHost for SP1Host {
    type Input<'a> = SP1ProofInputBuilder;
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

    fn extract_serde_public_output<T: Serialize + DeserializeOwned>(
        public_values: &PublicValues,
    ) -> ZkVmResult<T> {
        let public_params: T = bincode::deserialize(public_values.as_bytes())
            .map_err(|e| ZkVmError::OutputExtractionError { source: e.into() })?;
        Ok(public_params)
    }

    fn get_elf(&self) -> &[u8] {
        &self.proving_key.elf
    }

    fn get_verification_key(&self) -> VerificationKey {
        let verification_key = bincode::serialize(&self.proving_key.vk).unwrap();
        VerificationKey::new(verification_key)
    }

    fn get_verification_key_commitment(&self) -> VerificationKeyCommitment {
        VerificationKeyCommitment::new(self.proving_key.vk.hash_u32())
    }

    fn verify_inner(&self, proof: &SP1ProofReceipt) -> ZkVmResult<()> {
        let client = ProverClient::from_env();
        client
            .verify(proof.as_ref(), &self.proving_key.vk)
            .map_err(|e| ZkVmError::ProofVerificationError(e.to_string()))?;

        Ok(())
    }
}

impl fmt::Debug for SP1Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sp1_{}", self.proving_key.vk.bytes32())
    }
}
