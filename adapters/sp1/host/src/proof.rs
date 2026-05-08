use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues, SP1PublicValues};
use zkaleido::{
    DataFormatError, Mismatched, ProgramId, Proof, ProofMetadata, ProofReceipt,
    ProofReceiptWithMetadata, PublicValues, ZkVm, ZkVmProofError,
};

#[derive(Debug, Clone)]
pub struct SP1ProofReceipt {
    inner: SP1ProofWithPublicValues,
    program_id: ProgramId,
}

impl SP1ProofReceipt {
    pub fn new(inner: SP1ProofWithPublicValues, program_id: ProgramId) -> Self {
        Self { inner, program_id }
    }

    pub fn into_inner(self) -> SP1ProofWithPublicValues {
        self.inner
    }

    pub fn inner(&self) -> &SP1ProofWithPublicValues {
        &self.inner
    }

    pub fn program_id(&self) -> &ProgramId {
        &self.program_id
    }
}

impl AsRef<SP1ProofWithPublicValues> for SP1ProofReceipt {
    fn as_ref(&self) -> &SP1ProofWithPublicValues {
        &self.inner
    }
}

impl TryFrom<ProofReceiptWithMetadata> for SP1ProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: ProofReceiptWithMetadata) -> Result<Self, Self::Error> {
        SP1ProofReceipt::try_from(&value)
    }
}

impl TryFrom<&ProofReceiptWithMetadata> for SP1ProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: &ProofReceiptWithMetadata) -> Result<Self, Self::Error> {
        let zkvm_in_proof = value.metadata().zkvm();
        if zkvm_in_proof != &ZkVm::SP1 {
            Err(Mismatched {
                expected: ZkVm::SP1,
                actual: *zkvm_in_proof,
            })?
        }

        let version_in_proof = value.metadata().version().to_string();
        let sp1_version = sp1_sdk::SP1_CIRCUIT_VERSION.to_string();
        if version_in_proof != sp1_version {
            Err(Mismatched {
                expected: sp1_version.clone(),
                actual: version_in_proof,
            })?
        }

        let public_values = SP1PublicValues::from(value.receipt().public_values().as_bytes());
        let proof: SP1Proof = bincode::deserialize(value.receipt().proof().as_bytes())
            .map_err(|e| ZkVmProofError::DataFormat(DataFormatError::Serde(e.to_string())))?;
        let proof_receipt = SP1ProofWithPublicValues {
            proof,
            public_values,
            sp1_version,
            tee_proof: None,
        };
        let program_id = value.metadata().program_id().clone();
        Ok(SP1ProofReceipt::new(proof_receipt, program_id))
    }
}

impl TryFrom<SP1ProofReceipt> for ProofReceiptWithMetadata {
    type Error = ZkVmProofError;
    fn try_from(value: SP1ProofReceipt) -> Result<Self, Self::Error> {
        let sp1_receipt = value.as_ref();

        // If there's a Groth16 representation, just reuse its bytes;
        // otherwise, serialize the entire proof.
        let proof_bytes = match &sp1_receipt.proof {
            SP1Proof::Groth16(_) => sp1_receipt.bytes(),
            _ => bincode::serialize(&sp1_receipt.proof)
                .map_err(|e| ZkVmProofError::DataFormat(DataFormatError::Serde(e.to_string())))?,
        };

        let proof = Proof::new(proof_bytes);
        let public_values = PublicValues::new(sp1_receipt.public_values.to_vec());
        let receipt = ProofReceipt::new(proof, public_values);

        let sp1_version = sp1_sdk::SP1_CIRCUIT_VERSION.to_string();
        let metadata = ProofMetadata::new(ZkVm::SP1, value.program_id().clone(), sp1_version);

        Ok(ProofReceiptWithMetadata::new(receipt, metadata))
    }
}
