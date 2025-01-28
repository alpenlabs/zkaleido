use std::{fmt, sync::Arc};

use zkaleido::{
    Proof, ProofReceipt, ProofType, PublicValues, VerificationKey, VerificationKeyCommitment,
    ZkVmError, ZkVmHost, ZkVmResult,
};

use crate::{env::NativeMachine, input::NativeMachineInputBuilder, proof::NativeProofReceipt};

type ProcessProofFn = dyn Fn(&NativeMachine) -> ZkVmResult<()> + Send + Sync;

#[derive(Clone)]
pub struct NativeHost {
    pub process_proof: Arc<Box<ProcessProofFn>>,
}

impl ZkVmHost for NativeHost {
    type Input<'a> = NativeMachineInputBuilder;
    type ZkVmProofReceipt = NativeProofReceipt;

    fn prove_inner<'a>(
        &self,
        native_machine: NativeMachine,
        _proof_type: ProofType,
    ) -> ZkVmResult<NativeProofReceipt> {
        let (public_values, _) = self.execute(native_machine)?;
        let proof = Proof::default();
        Ok(ProofReceipt::new(proof, public_values).try_into()?)
    }

    fn execute<'a>(&self, native_machine: NativeMachine) -> ZkVmResult<(PublicValues, u64)> {
        (self.process_proof)(&native_machine)?;
        let output = native_machine.state.borrow().output.clone();
        let public_values = PublicValues::new(output);
        // Since we don't care about cycle counts in the native mode, setting it to zero
        Ok((public_values, 0))
    }

    fn get_elf(&self) -> &[u8] {
        &[]
    }

    fn get_verification_key(&self) -> VerificationKey {
        VerificationKey::default()
    }

    fn get_verification_key_commitment(&self) -> VerificationKeyCommitment {
        VerificationKeyCommitment::new([0u32; 8])
    }

    fn extract_serde_public_output<T: serde::Serialize + serde::de::DeserializeOwned>(
        public_values_raw: &PublicValues,
    ) -> ZkVmResult<T> {
        let public_params: T = bincode::deserialize(public_values_raw.as_bytes())
            .map_err(|e| ZkVmError::OutputExtractionError { source: e.into() })?;
        Ok(public_params)
    }

    fn verify_inner(&self, _proof: &NativeProofReceipt) -> ZkVmResult<()> {
        Ok(())
    }
}

impl fmt::Debug for NativeHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native")
    }
}
