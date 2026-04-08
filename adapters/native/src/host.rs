use std::{env, fmt, sync::Arc};

#[cfg(feature = "remote-prover")]
use async_trait::async_trait;
use k256::schnorr::{
    signature::{Signer, Verifier},
    Signature, SigningKey,
};
use rand_core::OsRng;
use zkaleido::{
    DataFormatError, ExecutionSummary, ProgramId, Proof, ProofMetadata, ProofReceipt,
    ProofReceiptWithMetadata, ProofType, PublicValues, VerifyingKey, ZkVm, ZkVmError, ZkVmExecutor,
    ZkVmHost, ZkVmOutputExtractor, ZkVmProver, ZkVmResult, ZkVmTypedVerifier, ZkVmVkProvider,
};
#[cfg(feature = "remote-prover")]
use zkaleido::{RemoteProofStatus, ZkVmRemoteProver};

use crate::{env::NativeMachine, input::NativeMachineInputBuilder, proof::NativeProofReceipt};

type ProcessProofFn = dyn Fn(&NativeMachine) -> ZkVmResult<()> + Send + Sync;

/// A native host that holds a reference to a proof-processing function and a Schnorr signing key.
///
/// This struct can be cloned cheaply (due to the internal [`Arc`]), and used by various
/// parts of the application to execute native proofs with Schnorr signature-based verification.
/// The signing key is used to sign public values during proof generation and verify them during
/// verification.
#[derive(Clone)]
pub struct NativeHost {
    /// A function wrapped in [`Arc`] and [`Box`] that processes proofs for a
    /// [`NativeMachine`].
    ///
    /// By storing the function in a dynamic pointer (`Box<dyn ...>`) inside an
    /// [`Arc`], multiple host instances or threads can share the same proof
    /// logic without needing to replicate code or data.
    process_fn: Arc<Box<ProcessProofFn>>,

    /// The Schnorr signing key used for signing public values during proof generation
    /// and verifying signatures during proof verification.
    schnorr_key: SigningKey,
}

impl NativeHost {
    /// Creates a new [`NativeHost`] with the given proof processing function.
    ///
    /// Generates a fresh Schnorr signing key pair to sign and verify proof outputs,
    /// providing authenticity guarantees for native execution.
    ///
    /// This method accepts infallible functions that return `()`. For functions that
    /// may fail and return `ZkVmResult<()>`, use [`new_fallible`](Self::new_fallible) instead.
    pub fn new<F>(process_fn: F) -> Self
    where
        F: Fn(&NativeMachine) + Send + Sync + 'static,
    {
        let schnorr_key = SigningKey::random(&mut OsRng);
        Self {
            process_fn: Arc::new(Box::new(move |zkvm: &NativeMachine| -> ZkVmResult<()> {
                process_fn(zkvm);
                Ok(())
            })),
            schnorr_key,
        }
    }

    /// Creates a new [`NativeHost`] with a fallible proof processing function.
    ///
    /// Use this method when your processing function may fail and returns `ZkVmResult<()>`.
    /// For infallible functions that return `()`, use [`new`](Self::new) instead.
    pub fn new_fallible<F>(process_fn: F) -> Self
    where
        F: Fn(&NativeMachine) -> ZkVmResult<()> + Send + Sync + 'static,
    {
        let schnorr_key = SigningKey::random(&mut OsRng);
        Self {
            process_fn: Arc::new(Box::new(process_fn)),
            schnorr_key,
        }
    }
}

impl ZkVmHost for NativeHost {}

impl ZkVmExecutor for NativeHost {
    type Input<'a> = NativeMachineInputBuilder;
    fn execute<'a>(&self, native_machine: NativeMachine) -> ZkVmResult<ExecutionSummary> {
        (self.process_fn)(&native_machine)?;
        let output = native_machine.state.borrow().output.clone();
        let public_values = PublicValues::new(output);
        // There is no straightforward equivalent of cycles and gas for native execution
        Ok(ExecutionSummary::new(public_values, 0, None))
    }

    /// Returns an empty slice as there is no ELF in native mode.
    fn get_elf(&self) -> &[u8] {
        &[]
    }

    fn save_trace(&self, _trace_name: &str) {}

    fn program_id(&self) -> zkaleido::ProgramId {
        ProgramId(self.schnorr_key.verifying_key().to_bytes().into())
    }
}

impl ZkVmProver for NativeHost {
    type ZkVmProofReceipt = NativeProofReceipt;

    fn prove_inner<'a>(
        &self,
        native_machine: NativeMachine,
        _proof_type: ProofType,
    ) -> ZkVmResult<NativeProofReceipt> {
        let execution_result = self.execute(native_machine)?;
        let public_values = execution_result.into_public_values();
        // Sign the public values using the Schnorr signing key
        let signature = self.schnorr_key.sign(public_values.as_bytes());
        let proof = Proof::new(signature.to_bytes().to_vec());
        let receipt = ProofReceipt::new(proof, public_values);

        let version: &str = env!("CARGO_PKG_VERSION");
        let metadata = ProofMetadata::new(ZkVm::Native, ProgramId([0u8; 32]), version.to_string());

        let receipt = ProofReceiptWithMetadata::new(receipt, metadata);
        Ok(receipt.try_into()?)
    }
}

impl ZkVmTypedVerifier for NativeHost {
    type ZkVmProofReceipt = NativeProofReceipt;

    fn verify_inner(&self, proof: &NativeProofReceipt) -> ZkVmResult<()> {
        let receipt: ProofReceiptWithMetadata = proof
            .clone()
            .try_into()
            .map_err(ZkVmError::InvalidProofReceipt)?;
        let signature = Signature::try_from(receipt.receipt().proof().as_bytes())
            .map_err(|e| ZkVmError::ProofVerificationError(format!("invalid signature: {e}")))?;
        // Verify the Schnorr signature over the public values
        self.schnorr_key
            .verifying_key()
            .verify(receipt.receipt().public_values().as_bytes(), &signature)
            .map_err(|e| {
                ZkVmError::ProofVerificationError(format!("signature verification failed: {e}"))
            })?;

        Ok(())
    }
}

impl ZkVmVkProvider for NativeHost {
    fn vk(&self) -> VerifyingKey {
        // Return the Schnorr public key (verifying key) as the verifying key
        let schnorr_public_key = self.schnorr_key.verifying_key().to_bytes().to_vec();
        VerifyingKey::new(schnorr_public_key)
    }
}

impl ZkVmOutputExtractor for NativeHost {
    fn extract_serde_public_output<T: serde::Serialize + serde::de::DeserializeOwned>(
        public_values_raw: &PublicValues,
    ) -> ZkVmResult<T> {
        let public_params: T = bincode::deserialize(public_values_raw.as_bytes()).map_err(|e| {
            ZkVmError::OutputExtractionError {
                source: DataFormatError::Serde(e.to_string()),
            }
        })?;
        Ok(public_params)
    }
}

impl fmt::Debug for NativeHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native")
    }
}

/// A proof identifier for native execution.
///
/// Since `NativeHost` executes proofs synchronously, the proof ID contains the
/// encoded proof receipt itself as raw bytes, making the proof immediately available.
/// Displayed as a hex string for logging.
#[cfg(feature = "remote-prover")]
#[derive(Debug, Clone)]
pub struct NativeProofId(Vec<u8>);

#[cfg(feature = "remote-prover")]
impl fmt::Display for NativeProofId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

#[cfg(feature = "remote-prover")]
impl From<NativeProofId> for Vec<u8> {
    fn from(id: NativeProofId) -> Self {
        id.0
    }
}

#[cfg(feature = "remote-prover")]
impl From<Vec<u8>> for NativeProofId {
    fn from(bytes: Vec<u8>) -> Self {
        NativeProofId(bytes)
    }
}

/// Implementation of `ZkVmRemoteProver` for `NativeHost`.
///
/// Since `NativeHost` executes proofs synchronously, this implementation:
/// - Runs the proof immediately in `start_proving`
/// - Serializes the result as the proof ID
/// - Returns `Completed` status and decodes the proof on retrieval
///
/// Combined with the blanket impl `impl<T: ZkVmHost + ZkVmRemoteProver> ZkVmRemoteHost for T`,
/// this automatically gives `NativeHost` the `ZkVmRemoteHost` trait, allowing it to work
/// seamlessly with async/remote proving interfaces.
#[cfg(feature = "remote-prover")]
#[async_trait(?Send)]
impl ZkVmRemoteProver for NativeHost {
    type ProofId = NativeProofId;

    async fn start_proving<'a>(
        &self,
        input: <Self::Input<'a> as zkaleido::ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<NativeProofId> {
        // Execute proof synchronously
        let proof_receipt = self.prove(input, proof_type)?;

        // Encode the proof receipt as the proof ID
        Ok(NativeProofId(proof_receipt.encode()))
    }

    async fn get_status(&self, _id: &NativeProofId) -> ZkVmResult<RemoteProofStatus> {
        // Native proofs are always immediately available.
        Ok(RemoteProofStatus::Completed)
    }

    async fn get_proof(&self, id: &NativeProofId) -> ZkVmResult<ProofReceiptWithMetadata> {
        ProofReceiptWithMetadata::decode(&id.0)
    }
}
