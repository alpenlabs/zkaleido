use serde::{Serialize, de::DeserializeOwned};
use sp1_sdk::{
    ProvingKey, StatusCode,
    blocking::{Prover, ProverClient},
};
use zkaleido::{
    DataFormatError, PublicValues, VerifyingKey, ZkVmError, ZkVmOutputExtractor, ZkVmResult,
    ZkVmTypedVerifier, ZkVmVkProvider,
};

use crate::{SP1Host, proof::SP1ProofReceipt};

impl ZkVmTypedVerifier for SP1Host {
    type ZkVmProofReceipt = SP1ProofReceipt;
    fn verify_inner(&self, proof: &SP1ProofReceipt) -> ZkVmResult<()> {
        let client = ProverClient::builder().light().build();
        let vkey = self.proving_key.verifying_key();
        client
            .verify(proof.inner(), vkey, Some(StatusCode::SUCCESS))
            .map_err(|e| ZkVmError::ProofVerificationError(e.to_string()))
    }
}

impl ZkVmVkProvider for SP1Host {
    fn vk(&self) -> VerifyingKey {
        let verification_key = bincode::serialize(self.proving_key.verifying_key()).unwrap();
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
