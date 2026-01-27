use std::{env, fmt, sync::Arc};

use async_trait::async_trait;
use k256::schnorr::{
    signature::{Signer, Verifier},
    Signature, SigningKey,
};
use rand_core::OsRng;
use zkaleido::{
    ExecutionSummary, Proof, ProofMetadata, ProofReceipt, ProofReceiptWithMetadata, ProofType,
    PublicValues, VerifyingKey, VerifyingKeyCommitment, ZkVm, ZkVmError, ZkVmExecutor, ZkVmHost,
    ZkVmOutputExtractor, ZkVmProver, ZkVmRemoteProver, ZkVmResult, ZkVmTypedVerifier,
    ZkVmVkProvider,
};

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
        let metadata = ProofMetadata::new(ZkVm::Native, version.to_string());

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

    fn vk_commitment(&self) -> VerifyingKeyCommitment {
        VerifyingKeyCommitment::new([0u32; 8])
    }
}

impl ZkVmOutputExtractor for NativeHost {
    fn extract_serde_public_output<T: serde::Serialize + serde::de::DeserializeOwned>(
        public_values_raw: &PublicValues,
    ) -> ZkVmResult<T> {
        let public_params: T = bincode::deserialize(public_values_raw.as_bytes())
            .map_err(|e| ZkVmError::OutputExtractionError { source: e.into() })?;
        Ok(public_params)
    }
}

impl fmt::Debug for NativeHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native")
    }
}

/// Implementation of `ZkVmRemoteProver` for `NativeHost`.
///
/// Since `NativeHost` executes proofs synchronously, this implementation:
/// - Runs the proof immediately in `start_proving`
/// - Serializes the result and hex-encodes it as the "proof ID"
/// - Deserializes and returns the proof in `get_proof_if_ready_inner`
///
/// Combined with the blanket impl `impl<T: ZkVmHost + ZkVmRemoteProver> ZkVmRemoteHost for T`,
/// this automatically gives `NativeHost` the `ZkVmRemoteHost` trait, allowing it to work
/// seamlessly with async/remote proving interfaces.
#[async_trait(?Send)]
impl ZkVmRemoteProver for NativeHost {
    async fn start_proving<'a>(
        &self,
        input: <Self::Input<'a> as zkaleido::ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<String> {
        // Execute proof synchronously
        let proof_receipt = self.prove(input, proof_type)?;

        // Serialize using bincode
        let serialized = bincode::serialize(&proof_receipt)
            .map_err(|e| ZkVmError::InvalidProofReceipt(e.into()))?;

        // Encode as hex to use as "proof ID"
        Ok(hex::encode(serialized))
    }

    async fn get_proof_if_ready_inner(
        &self,
        id: String,
    ) -> ZkVmResult<Option<Self::ZkVmProofReceipt>> {
        // Decode the hex-encoded proof
        let decoded = hex::decode(&id).map_err(|_| {
            ZkVmError::InvalidProofReceipt(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid hex encoding").into(),
            )
        })?;

        // Deserialize the ProofReceiptWithMetadata
        let proof: ProofReceiptWithMetadata =
            bincode::deserialize(&decoded).map_err(|e| ZkVmError::InvalidProofReceipt(e.into()))?;

        // Convert to NativeProofReceipt
        let native_receipt = proof.try_into().map_err(ZkVmError::InvalidProofReceipt)?;

        Ok(Some(native_receipt))
    }
}
