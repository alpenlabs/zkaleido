use std::{fmt, sync::Arc};

use zkaleido::{
    Proof, ProofReceipt, ProofType, PublicValues, VerifyingKey, VerifyingKeyCommitment, ZkVm,
    ZkVmError, ZkVmExecutor, ZkVmHost, ZkVmOutputExtractor, ZkVmProver, ZkVmResult, ZkVmVerifier,
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
        let public_values = self.execute(native_machine)?;
        let proof = Proof::default();
        Ok(ProofReceipt::new(proof, public_values, ZkVm::Native).try_into()?)
    }
}

impl ZkVmVerifier for NativeHost {
    type ZkVmProofReceipt = NativeProofReceipt;
    fn vk(&self) -> VerifyingKey {
        VerifyingKey::default()
    }

    fn vk_commitment(&self) -> VerifyingKeyCommitment {
        VerifyingKeyCommitment::new([0u32; 8])
    }

    fn verify_inner(&self, _proof: &NativeProofReceipt) -> ZkVmResult<()> {
        Ok(())
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
