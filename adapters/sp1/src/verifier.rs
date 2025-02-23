use serde::{de::DeserializeOwned, Serialize};
use sp1_sdk::{HashableKey, ProverClient};
use zkaleido::{
    PublicValues, VerificationKey, VerificationKeyCommitment, ZkVmError, ZkVmResult, ZkVmVerifier,
};

use crate::{proof::SP1ProofReceipt, SP1Host};

impl ZkVmVerifier for SP1Host {
    type ZkVmProofReceipt = SP1ProofReceipt;
    fn extract_serde_public_output<T: Serialize + DeserializeOwned>(
        public_values: &PublicValues,
    ) -> ZkVmResult<T> {
        let public_params: T = bincode::deserialize(public_values.as_bytes())
            .map_err(|e| ZkVmError::OutputExtractionError { source: e.into() })?;
        Ok(public_params)
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
