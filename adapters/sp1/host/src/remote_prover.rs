use std::{fmt, future::IntoFuture};

use sp1_sdk::{
    NetworkProver, ProveRequest, Prover, ProvingKey,
    env::{EnvProver, EnvProvingKey},
    network::{
        B256, Error as NetworkError,
        proto::{
            GetProofRequestStatusResponse,
            types::{ExecutionStatus, FulfillmentStatus},
        },
    },
};
use zkaleido::{
    ProofReceiptWithMetadata, ProofType, RemoteProofFailureReason, RemoteProofStatus, ZkVmError,
    ZkVmExecutor, ZkVmInputBuilder, ZkVmRemoteProver, ZkVmResult,
};

use crate::{
    SP1Host,
    proof::SP1ProofReceipt,
    prover::{ensure_clean_exit, to_sp1_mode},
};

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

#[async_trait::async_trait]
impl ZkVmRemoteProver for SP1Host {
    type ProofId = Sp1ProofId;

    async fn start_proving<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<Sp1ProofId> {
        let client = self.network_client()?;

        let pk = match &self.proving_key {
            EnvProvingKey::Network { pk, .. } => pk,
            _ => unreachable!("we validate that the client is network above"),
        };

        // Pre-flight: run an honest local execute. Without this, the SDK's
        // simulation inside `.request().await` would happily submit a
        // request whose guest panics — the SDK's simulation doesn't
        // enforce exit_code. We then pass the resulting cycle/gas to the
        // network builder with `.skip_simulation(true)` so the SDK does
        // not re-run the executor on the same input. Net cost: one
        // simulation per submission, ours, which fails fast on panic.
        //
        // We drive SP1's async executor directly with `.await` instead of
        // calling [`ZkVmExecutor::execute`] (the sync trait method).
        // The sync path routes through [`crate::prover::block_on_async`],
        // which uses [`tokio::task::block_in_place`] (thus making its
        // usage in async context here error-prone and tokio runtime
        // dependent).
        let elf = self.proving_key.elf().clone();
        let (_, report) = self
            .client
            .execute(elf, input.clone())
            .into_future()
            .await
            .map_err(|e| ZkVmError::ExecutionError(e.to_string()))?;
        if self.config.require_success {
            ensure_clean_exit(&report)?;
        }
        // Mirrors `sp1_sdk::network::DEFAULT_GAS_LIMIT` (pub(crate) so we
        // cannot import it). The SDK uses the same fallback when its own
        // simulation returns a report with `gas = None`.
        const DEFAULT_GAS_LIMIT: u64 = 1_000_000_000;
        let cycle_limit = report.total_instruction_count();
        let gas_limit = report.gas().unwrap_or(DEFAULT_GAS_LIMIT);

        let mut builder = client
            .prove(pk, input)
            .strategy(self.config.proof_strategy)
            .mode(to_sp1_mode(proof_type))
            .skip_simulation(true)
            .cycle_limit(cycle_limit)
            .gas_limit(gas_limit);
        if let Some(deadline) = self.config.deadline {
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
        let client = self.network_client()?;
        let (status, _) = client
            .get_proof_status(id.0)
            .await
            .map_err(|e| ZkVmError::NetworkRetryableError(e.to_string()))?;

        Ok(convert_proof_status(status))
    }

    async fn get_proof(&self, id: &Sp1ProofId) -> ZkVmResult<ProofReceiptWithMetadata> {
        let client = self.network_client()?;
        let (_, proof) = client
            .get_proof_status(id.0)
            .await
            .map_err(|e| ZkVmError::NetworkRetryableError(e.to_string()))?;

        let proof = proof.ok_or(ZkVmError::ProofNotReady)?;
        SP1ProofReceipt::new(proof, self.program_id())
            .try_into()
            .map_err(ZkVmError::InvalidProofReceipt)
    }
}

impl SP1Host {
    /// Extracts the network-specific [`NetworkProver`] from the host's
    /// [`EnvProver`]. Returns an error when the host was initialized with a
    /// non-network backend.
    fn network_client(&self) -> ZkVmResult<&NetworkProver> {
        let client = match &self.client {
            EnvProver::Network(np) => np,
            _ => {
                return Err(ZkVmError::ProofGenerationError(
                    "SP1Host is not configured with the network prover".into(),
                ));
            }
        };

        Ok(client)
    }
}

/// Converts an SP1 proof status response into a backend-agnostic [`RemoteProofStatus`].
fn convert_proof_status(response: GetProofRequestStatusResponse) -> RemoteProofStatus {
    let execution_status = ExecutionStatus::try_from(response.execution_status())
        .unwrap_or(ExecutionStatus::UnspecifiedExecutionStatus);

    if execution_status == ExecutionStatus::Unexecutable {
        return RemoteProofStatus::Failed(RemoteProofFailureReason::Unexecutable);
    }

    let fulfillment_status = FulfillmentStatus::try_from(response.fulfillment_status())
        .unwrap_or(FulfillmentStatus::UnspecifiedFulfillmentStatus);

    match fulfillment_status {
        FulfillmentStatus::Requested => RemoteProofStatus::Requested,
        FulfillmentStatus::Assigned => RemoteProofStatus::InProgress,
        FulfillmentStatus::Fulfilled => RemoteProofStatus::Completed,
        FulfillmentStatus::Unfulfillable => {
            RemoteProofStatus::Failed(RemoteProofFailureReason::Unfulfillable)
        }
        FulfillmentStatus::Reverted => {
            RemoteProofStatus::Failed(RemoteProofFailureReason::Reverted)
        }
        FulfillmentStatus::Expired => RemoteProofStatus::Failed(RemoteProofFailureReason::Expired),
        FulfillmentStatus::UnspecifiedFulfillmentStatus => RemoteProofStatus::Failed(
            RemoteProofFailureReason::Other("unspecified fulfillment status".to_string()),
        ),
    }
}
