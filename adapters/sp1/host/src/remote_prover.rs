use std::fmt;

use sp1_sdk::{
    network::{
        proto::types::{ExecutionStatus, FulfillmentStatus, GetProofRequestStatusResponse},
        FulfillmentStrategy, B256,
    },
    ProverClient, SP1ProofMode,
};
use zkaleido::{
    ProofReceiptWithMetadata, ProofType, RemoteProofStatus, ZkVmError, ZkVmExecutor,
    ZkVmInputBuilder, ZkVmRemoteProver, ZkVmResult,
};

use crate::{proof::SP1ProofReceipt, SP1Host};

/// A typed proof identifier for the SP1 network prover.
///
/// Wraps [`B256`] to implement the byte-conversion traits (`Into<Vec<u8>>` and
/// `TryFrom<Vec<u8>>`) required by [`ZkVmRemoteProver::ProofId`], which cannot
/// be implemented directly on the foreign `B256` type.
#[derive(Debug, Clone)]
pub struct Sp1ProofId(B256);

impl fmt::Display for Sp1ProofId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Sp1ProofId> for Vec<u8> {
    fn from(id: Sp1ProofId) -> Self {
        id.0.as_slice().to_vec()
    }
}

impl TryFrom<Vec<u8>> for Sp1ProofId {
    type Error = <B256 as TryFrom<&'static [u8]>>::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        B256::try_from(bytes.as_slice()).map(Sp1ProofId)
    }
}

#[async_trait::async_trait(?Send)]
impl ZkVmRemoteProver for SP1Host {
    type ProofId = Sp1ProofId;

    async fn start_proving<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<Sp1ProofId> {
        let client = ProverClient::builder().network().build();

        let strategy = std::env::var("SP1_PROOF_STRATEGY")
            .ok()
            .and_then(|s| FulfillmentStrategy::from_str_name(&s.to_ascii_uppercase()))
            .unwrap_or(FulfillmentStrategy::Auction);

        let mode = match proof_type {
            ProofType::Core => SP1ProofMode::Core,
            ProofType::Compressed => SP1ProofMode::Compressed,
            ProofType::Groth16 => SP1ProofMode::Groth16,
        };

        let pk = &self.proving_key;
        let request_id = client
            .prove(pk, &input)
            .strategy(strategy)
            .mode(mode)
            .request_async()
            .await
            .map_err(|e| ZkVmError::ProofGenerationError(e.to_string()))?;

        Ok(Sp1ProofId(request_id))
    }

    async fn get_status(&self, id: &Sp1ProofId) -> ZkVmResult<RemoteProofStatus> {
        let client = ProverClient::builder().network().build();
        let (status, _) = client
            .get_proof_status(id.0)
            .await
            .map_err(|e| ZkVmError::NetworkRetryableError(e.to_string()))?;

        Ok(convert_proof_status(status))
    }

    async fn get_proof(&self, id: &Sp1ProofId) -> ZkVmResult<ProofReceiptWithMetadata> {
        let client = ProverClient::builder().network().build();
        let (_, proof) = client
            .get_proof_status(id.0)
            .await
            .map_err(|e| ZkVmError::NetworkRetryableError(e.to_string()))?;

        match proof {
            Some(proof) => {
                let sp1_receipt = SP1ProofReceipt::new(proof, self.program_id());
                sp1_receipt
                    .try_into()
                    .map_err(ZkVmError::InvalidProofReceipt)
            }
            None => Err(ZkVmError::ProofNotReady),
        }
    }
}

/// Converts an SP1 proof status response into a backend-agnostic [`RemoteProofStatus`].
fn convert_proof_status(response: GetProofRequestStatusResponse) -> RemoteProofStatus {
    let execution_status = ExecutionStatus::try_from(response.execution_status)
        .unwrap_or(ExecutionStatus::UnspecifiedExecutionStatus);

    if execution_status == ExecutionStatus::Unexecutable {
        return RemoteProofStatus::Failed("unexecutable".to_string());
    }

    let fulfillment_status = FulfillmentStatus::try_from(response.fulfillment_status)
        .unwrap_or(FulfillmentStatus::UnspecifiedFulfillmentStatus);

    match fulfillment_status {
        FulfillmentStatus::Requested => RemoteProofStatus::Requested,
        FulfillmentStatus::Assigned => RemoteProofStatus::InProgress,
        FulfillmentStatus::Fulfilled => RemoteProofStatus::Completed,
        FulfillmentStatus::Unfulfillable => RemoteProofStatus::Failed("unfulfillable".to_string()),
        FulfillmentStatus::UnspecifiedFulfillmentStatus => RemoteProofStatus::Unknown,
    }
}
