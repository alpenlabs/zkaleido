use std::{env, fmt, sync::Arc};

use async_trait::async_trait;
use zkaleido::{
    Proof, ProofMetadata, ProofReceipt, ProofReceiptWithMetadata, ProofType, PublicValues,
    VerifyingKey, VerifyingKeyCommitment, ZkVm, ZkVmError, ZkVmExecutor, ZkVmHost,
    ZkVmOutputExtractor, ZkVmProver, ZkVmRemoteProver, ZkVmResult, ZkVmTypedVerifier,
    ZkVmVkProvider,
};

use crate::{env::NativeMachine, input::NativeMachineInputBuilder, proof::NativeProofReceipt};

type ProcessProofFn = dyn Fn(&NativeMachine) -> ZkVmResult<()> + Send + Sync;

/// A native host that holds a reference to a proof-processing function (`process_proof`).
///
/// This struct can be cloned cheaply (due to the internal [`Arc`]), and used by various
/// parts of the application to execute native proofs or validations without
/// requiring a real cryptographic backend.
#[derive(Clone)]
pub struct NativeHost {
    /// A function wrapped in [`Arc`] and [`Box`] that processes proofs for a
    /// [`NativeMachine`].
    ///
    /// By storing the function in a dynamic pointer (`Box<dyn ...>`) inside an
    /// [`Arc`], multiple host instances or threads can share the same proof
    /// logic without needing to replicate code or data.
    pub process_proof: Arc<Box<ProcessProofFn>>,
}

impl ZkVmHost for NativeHost {}

impl ZkVmExecutor for NativeHost {
    type Input<'a> = NativeMachineInputBuilder;
    fn execute<'a>(&self, native_machine: NativeMachine) -> ZkVmResult<PublicValues> {
        (self.process_proof)(&native_machine)?;
        let output = native_machine.state.borrow().output.clone();
        let public_values = PublicValues::new(output);
        Ok(public_values)
    }

    /// Returns an empty slice as there is no ELF in native mode.
    fn get_elf(&self) -> &[u8] {
        &[]
    }

    /// Returns 0 as cycle counting is not applicable in native mode.
    ///
    /// For RISC-V ZkVms, cycles are obtained by emulating execution and counting
    /// instructions. There is no straightforward equivalent for native execution.
    fn get_cycles<'a>(
        &self,
        _input: <Self::Input<'a> as zkaleido::ZkVmInputBuilder<'a>>::Input,
    ) -> ZkVmResult<u64> {
        Ok(0)
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
        let public_values = self.execute(native_machine)?;
        let proof = Proof::default();
        let receipt = ProofReceipt::new(proof, public_values);

        let version: &str = env!("CARGO_PKG_VERSION");
        let metadata = ProofMetadata::new(ZkVm::Native, version.to_string());

        let receipt = ProofReceiptWithMetadata::new(receipt, metadata);
        Ok(receipt.try_into()?)
    }
}

impl ZkVmTypedVerifier for NativeHost {
    type ZkVmProofReceipt = NativeProofReceipt;

    fn verify_inner(&self, _proof: &NativeProofReceipt) -> ZkVmResult<()> {
        Ok(())
    }
}

impl ZkVmVkProvider for NativeHost {
    fn vk(&self) -> VerifyingKey {
        VerifyingKey::default()
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
