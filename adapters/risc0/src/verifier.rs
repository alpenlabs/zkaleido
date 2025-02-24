use risc0_zkvm::Journal;
use serde::{de::DeserializeOwned, Serialize};
use zkaleido::{
    PublicValues, VerifyingKey, VerifyingKeyCommitment, ZkVmError, ZkVmResult, ZkVmVerifier,
};

use crate::{proof::Risc0ProofReceipt, Risc0Host};

impl ZkVmVerifier for Risc0Host {
    type ZkVmProofReceipt = Risc0ProofReceipt;

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

    fn vk(&self) -> VerifyingKey {
        VerifyingKey::new(self.vk().as_bytes().to_vec())
    }

    fn vk_commitment(&self) -> VerifyingKeyCommitment {
        VerifyingKeyCommitment::new(self.vk().into())
    }

    fn verify_inner(&self, proof: &Risc0ProofReceipt) -> ZkVmResult<()> {
        proof
            .as_ref()
            .verify(self.vk())
            .map_err(|e| ZkVmError::ProofVerificationError(e.to_string()))?;
        Ok(())
    }
}
