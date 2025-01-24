use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues, SP1PublicValues};
use strata_zkvm::{Proof, ProofReceipt, PublicValues, ZkVmProofError};

#[derive(Debug, Clone)]
pub struct SP1ProofReceipt(SP1ProofWithPublicValues);

impl SP1ProofReceipt {
    pub fn inner(self) -> SP1ProofWithPublicValues {
        self.0
    }
}

impl From<SP1ProofWithPublicValues> for SP1ProofReceipt {
    fn from(receipt: SP1ProofWithPublicValues) -> Self {
        SP1ProofReceipt(receipt)
    }
}

impl AsRef<SP1ProofWithPublicValues> for SP1ProofReceipt {
    fn as_ref(&self) -> &SP1ProofWithPublicValues {
        &self.0
    }
}

impl TryFrom<ProofReceipt> for SP1ProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: ProofReceipt) -> Result<Self, Self::Error> {
        SP1ProofReceipt::try_from(&value)
    }
}

impl TryFrom<&ProofReceipt> for SP1ProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: &ProofReceipt) -> Result<Self, Self::Error> {
        let public_values = SP1PublicValues::from(value.public_values().as_bytes());
        let proof: SP1Proof = bincode::deserialize(value.proof().as_bytes())
            .map_err(|e| ZkVmProofError::DataFormat(e.into()))?;
        let sp1_version = sp1_sdk::SP1_CIRCUIT_VERSION.to_string();
        let proof_receipt = SP1ProofWithPublicValues {
            proof,
            public_values,
            sp1_version,
        };
        Ok(SP1ProofReceipt(proof_receipt))
    }
}

impl TryFrom<SP1ProofReceipt> for ProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: SP1ProofReceipt) -> Result<Self, Self::Error> {
        let sp1_receipt = value.as_ref();

        // If there's a Groth16 representation, just reuse its bytes;
        // otherwise, serialize the entire proof.
        let proof_bytes = match sp1_receipt.proof.clone().try_as_groth_16() {
            Some(_) => sp1_receipt.bytes(),
            None => bincode::serialize(&sp1_receipt.proof)
                .map_err(|e| ZkVmProofError::DataFormat(e.into()))?,
        };

        let proof = Proof::new(proof_bytes);
        let public_values = PublicValues::new(sp1_receipt.public_values.to_vec());

        Ok(ProofReceipt::new(proof, public_values))
    }
}
