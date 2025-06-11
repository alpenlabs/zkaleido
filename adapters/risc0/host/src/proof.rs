use risc0_zkvm::{InnerReceipt, Receipt};
use zkaleido::{Proof, ProofReceipt, PublicValues, ZkVm, ZkVmProofError};

#[derive(Debug, Clone)]
pub struct Risc0ProofReceipt(Receipt);

impl Risc0ProofReceipt {
    pub fn inner(self) -> Receipt {
        self.0
    }
}

impl From<Receipt> for Risc0ProofReceipt {
    fn from(receipt: Receipt) -> Self {
        Risc0ProofReceipt(receipt)
    }
}

impl AsRef<Receipt> for Risc0ProofReceipt {
    fn as_ref(&self) -> &Receipt {
        &self.0
    }
}

impl TryFrom<ProofReceipt> for Risc0ProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: ProofReceipt) -> Result<Self, Self::Error> {
        Risc0ProofReceipt::try_from(&value)
    }
}

impl TryFrom<&ProofReceipt> for Risc0ProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: &ProofReceipt) -> Result<Self, Self::Error> {
        let journal = value.public_values().as_bytes().to_vec();
        let inner: InnerReceipt = bincode::deserialize(value.proof().as_bytes())
            .map_err(|e| ZkVmProofError::DataFormat(e.into()))?;
        Ok(Receipt::new(inner, journal).into())
    }
}

impl TryFrom<Risc0ProofReceipt> for ProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: Risc0ProofReceipt) -> Result<Self, Self::Error> {
        // If there's a Groth16 representation, directly use its bytes;
        // otherwise, serialize the entire proof.
        let proof_bytes = match value.0.inner.groth16() {
            Ok(receipt) => receipt.clone().seal,
            Err(_) => bincode::serialize(&value.0.inner)
                .map_err(|e| ZkVmProofError::DataFormat(e.into()))?,
        };
        let proof = Proof::new(proof_bytes);
        let public_values = PublicValues::new(value.0.journal.bytes.to_vec());
        Ok(ProofReceipt::new(proof, public_values, ZkVm::Risc0))
    }
}
