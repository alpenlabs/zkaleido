use risc0_zkvm::{InnerReceipt, Receipt, VERSION};
use zkaleido::{
    Mismatched, Proof, ProofMetadata, ProofReceipt, ProofReceiptWithMetadata, PublicValues, ZkVm,
    ZkVmProofError,
};

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

impl TryFrom<ProofReceiptWithMetadata> for Risc0ProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: ProofReceiptWithMetadata) -> Result<Self, Self::Error> {
        Risc0ProofReceipt::try_from(&value)
    }
}

impl TryFrom<&ProofReceiptWithMetadata> for Risc0ProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: &ProofReceiptWithMetadata) -> Result<Self, Self::Error> {
        let zkvm_in_proof = value.metadata().zkvm();
        if zkvm_in_proof != &ZkVm::Risc0 {
            Err(Mismatched {
                expected: ZkVm::Risc0,
                actual: *zkvm_in_proof,
            })?
        }

        let version_in_proof = value.metadata().version().to_string();
        let risc0_version = VERSION.to_string();
        if version_in_proof != risc0_version {
            Err(Mismatched {
                expected: risc0_version.clone(),
                actual: version_in_proof,
            })?
        }

        let journal = value.receipt().public_values().as_bytes().to_vec();
        let inner: InnerReceipt = bincode::deserialize(value.receipt().proof().as_bytes())
            .map_err(|e| ZkVmProofError::DataFormat(e.into()))?;
        Ok(Receipt::new(inner, journal).into())
    }
}

impl TryFrom<Risc0ProofReceipt> for ProofReceiptWithMetadata {
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
        let receipt = ProofReceipt::new(proof, public_values);

        let metadata = ProofMetadata::new(ZkVm::Risc0, risc0_zkvm::VERSION);
        Ok(ProofReceiptWithMetadata::new(receipt, metadata))
    }
}
