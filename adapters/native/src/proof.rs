use zkaleido::{ProofReceiptWithMetadata, ZkVmProofError};

#[derive(Debug, Clone)]
pub struct NativeProofReceipt(ProofReceiptWithMetadata);

impl TryFrom<ProofReceiptWithMetadata> for NativeProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: ProofReceiptWithMetadata) -> Result<Self, Self::Error> {
        Ok(NativeProofReceipt(value))
    }
}

impl TryFrom<NativeProofReceipt> for ProofReceiptWithMetadata {
    type Error = ZkVmProofError;
    fn try_from(value: NativeProofReceipt) -> Result<Self, Self::Error> {
        Ok(value.0)
    }
}
