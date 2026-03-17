use std::fmt::{Debug, Display};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use async_trait::async_trait;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{input::ZkVmInputBuilder, ProofReceiptWithMetadata, ProofType, ZkVmProver, ZkVmResult};

/// Status of a remote proof request.
///
/// Modeled after SP1's `FulfillmentStatus` but simplified to be backend-agnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum RemoteProofStatus {
    /// The proof request has been submitted but work has not started.
    Requested,
    /// The proof is actively being generated.
    InProgress,
    /// The proof has been generated and is ready for retrieval.
    Completed,
    /// The proof generation failed.
    Failed(String),
    /// The status could not be determined.
    Unknown,
}

/// A trait implemented by the prover of a zkVM program.
///
/// This trait extends [`ZkVmProver`] to support asynchronous remote proving operations.
/// It provides methods to start the proving process, check its status, and retrieve
/// the proof once it becomes available. Implementers of this trait typically handle
/// the remote communication required to generate and fetch proofs.
#[async_trait(?Send)]
pub trait ZkVmRemoteProver: ZkVmProver {
    /// A typed proof identifier returned by [`start_proving`](Self::start_proving).
    ///
    /// Must be displayable for logging, cloneable for repeated status queries, and
    /// convertible to/from `Vec<u8>` for persistent storage (e.g. in a database) so
    /// that proof status polling can be resumed across restarts.
    type ProofId: Debug + Display + Clone + Into<Vec<u8>> + TryFrom<Vec<u8>> + 'static;

    /// Starts the proving process for the given input and proof type.
    ///
    /// This method initiates the remote proof generation and returns a typed
    /// proof identifier that can be used to query the status and retrieve
    /// the proof later.
    async fn start_proving<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<Self::ProofId>;

    /// Checks the status of a remote proof request.
    async fn get_status(&self, id: &Self::ProofId) -> ZkVmResult<RemoteProofStatus>;

    /// Retrieves the completed proof as a [`ProofReceiptWithMetadata`].
    ///
    /// Returns an error if the proof is not ready. Callers should check
    /// [`get_status`](Self::get_status) first.
    async fn get_proof(&self, id: &Self::ProofId) -> ZkVmResult<ProofReceiptWithMetadata>;
}
