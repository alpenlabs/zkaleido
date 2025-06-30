use risc0_zkvm::Journal;
use serde::{de::DeserializeOwned, Serialize};
use zkaleido::{
    PublicValues, VerifyingKey, VerifyingKeyCommitment, ZkVmError, ZkVmOutputExtractor, ZkVmResult,
    ZkVmVerifier,
};

use crate::{proof::Risc0ProofReceipt, Risc0Host};

impl ZkVmVerifier for Risc0Host {
    type ZkVmProofReceipt = Risc0ProofReceipt;

    fn vk(&self) -> VerifyingKey {
        VerifyingKey::new(self.image_id().as_bytes().to_vec())
    }

    fn vk_commitment(&self) -> VerifyingKeyCommitment {
        VerifyingKeyCommitment::new(self.image_id().into())
    }

    fn verify_inner(&self, proof: &Risc0ProofReceipt) -> ZkVmResult<()> {
        proof
            .as_ref()
            .verify(self.image_id())
            .map_err(|e| ZkVmError::ProofVerificationError(e.to_string()))?;
        Ok(())
    }
}

impl ZkVmOutputExtractor for Risc0Host {
    fn extract_serde_public_output<T: Serialize + DeserializeOwned>(
        proof: &PublicValues,
    ) -> ZkVmResult<T> {
        let journal = Journal::new(proof.as_bytes().to_vec());
        journal
            .decode()
            .map_err(|e| ZkVmError::OutputExtractionError {
                source: zkaleido::DataFormatError::Serde(e.to_string()),
            })
    }
}
