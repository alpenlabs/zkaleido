use std::{env::var, fmt};

use sp1_sdk::{
    NetworkProver, ProveRequest, Prover, ProverClient, SP1ProofMode,
    network::{
        B256, Error as NetworkError, FulfillmentStrategy, NetworkMode,
        proto::{
            GetProofRequestStatusResponse,
            types::{ExecutionStatus, FulfillmentStatus},
        },
    },
};
use zkaleido::{
    ProofReceiptWithMetadata, ProofType, RemoteProofStatus, ZkVmError, ZkVmExecutor,
    ZkVmInputBuilder, ZkVmRemoteProver, ZkVmResult,
};

use crate::{SP1Host, proof::SP1ProofReceipt};

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
        let strategy = proof_strategy();
        let client = build_network_client(strategy).await;

        let mode = match proof_type {
            ProofType::Core => SP1ProofMode::Core,
            ProofType::Compressed => SP1ProofMode::Compressed,
            ProofType::Groth16 => SP1ProofMode::Groth16,
        };

        let pk = &self.proving_key;
        let mut builder = client.prove(pk, input).strategy(strategy).mode(mode);
        if let Some(deadline) = self.deadline {
            builder = builder.timeout(deadline);
        }
        let request_id =
            builder
                .request()
                .await
                .map_err(|e| match e.downcast_ref::<NetworkError>() {
                    Some(NetworkError::RpcError(status)) => {
                        ZkVmError::NetworkRetryableError(status.to_string())
                    }
                    _ => ZkVmError::ProofGenerationError(e.to_string()),
                })?;

        Ok(Sp1ProofId(request_id))
    }

    async fn get_status(&self, id: &Sp1ProofId) -> ZkVmResult<RemoteProofStatus> {
        let client = build_network_client(proof_strategy()).await;
        let (status, _) = client
            .get_proof_status(id.0)
            .await
            .map_err(|e| ZkVmError::NetworkRetryableError(e.to_string()))?;

        Ok(convert_proof_status(status))
    }

    async fn get_proof(&self, id: &Sp1ProofId) -> ZkVmResult<ProofReceiptWithMetadata> {
        let client = build_network_client(proof_strategy()).await;
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

/// Reads the requested fulfillment strategy from `SP1_PROOF_STRATEGY`,
/// defaulting to `Auction` when unset or unparseable.
fn proof_strategy() -> FulfillmentStrategy {
    var("SP1_PROOF_STRATEGY")
        .ok()
        .and_then(|s| FulfillmentStrategy::from_str_name(&s.to_ascii_uppercase()))
        .unwrap_or(FulfillmentStrategy::Auction)
}

/// Builds a [`NetworkProver`] client for the network mode that matches
/// `strategy`. `Reserved` strategy targets the reserved cluster; everything
/// else uses the default public network.
async fn build_network_client(strategy: FulfillmentStrategy) -> NetworkProver {
    if strategy == FulfillmentStrategy::Reserved {
        ProverClient::builder()
            .network_for(NetworkMode::Reserved)
            .build()
            .await
    } else {
        ProverClient::builder().network().build().await
    }
}

/// Converts an SP1 proof status response into a backend-agnostic [`RemoteProofStatus`].
fn convert_proof_status(response: GetProofRequestStatusResponse) -> RemoteProofStatus {
    let execution_status = ExecutionStatus::try_from(response.execution_status())
        .unwrap_or(ExecutionStatus::UnspecifiedExecutionStatus);

    if execution_status == ExecutionStatus::Unexecutable {
        return RemoteProofStatus::Failed("unexecutable".to_string());
    }

    let fulfillment_status = FulfillmentStatus::try_from(response.fulfillment_status())
        .unwrap_or(FulfillmentStatus::UnspecifiedFulfillmentStatus);

    match fulfillment_status {
        FulfillmentStatus::Requested => RemoteProofStatus::Requested,
        FulfillmentStatus::Assigned => RemoteProofStatus::InProgress,
        FulfillmentStatus::Fulfilled => RemoteProofStatus::Completed,
        FulfillmentStatus::Unfulfillable => RemoteProofStatus::Failed("unfulfillable".to_string()),
        // TODO: figure out when this is triggered
        // Is this what happens when we request proof request for id that isn't valid?
        FulfillmentStatus::UnspecifiedFulfillmentStatus => RemoteProofStatus::Unknown,
    }
}
