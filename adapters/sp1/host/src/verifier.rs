use serde::{Serialize, de::DeserializeOwned};
use sp1_sdk::ProverClient;
use zkaleido::{
    DataFormatError, PublicValues, VerifyingKey, ZkVmError, ZkVmOutputExtractor, ZkVmResult,
    ZkVmTypedVerifier, ZkVmVkProvider,
};

use crate::{SP1Host, proof::SP1ProofReceipt};

impl ZkVmTypedVerifier for SP1Host {
    type ZkVmProofReceipt = SP1ProofReceipt;
    fn verify_inner(&self, proof: &SP1ProofReceipt) -> ZkVmResult<()> {
        let client = ProverClient::from_env();
        client
            .verify(proof.as_ref(), &self.proving_key.vk)
            .map_err(|e| ZkVmError::ProofVerificationError(e.to_string()))?;

        Ok(())
    }
}

impl ZkVmVkProvider for SP1Host {
    fn vk(&self) -> VerifyingKey {
        let verification_key = bincode::serialize(&self.proving_key.vk).unwrap();
        VerifyingKey::new(verification_key)
    }
}

impl ZkVmOutputExtractor for SP1Host {
    fn extract_serde_public_output<T: Serialize + DeserializeOwned>(
        public_values: &PublicValues,
    ) -> ZkVmResult<T> {
        let public_params: T = bincode::deserialize(public_values.as_bytes()).map_err(|e| {
            ZkVmError::OutputExtractionError {
                source: DataFormatError::Serde(e.to_string()),
            }
        })?;
        Ok(public_params)
    }
}
