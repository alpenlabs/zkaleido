use std::{
    env::set_var,
    future::{Future, IntoFuture},
};

use hex::FromHex;
use sp1_core_executor::ExecutionReport;
use sp1_sdk::{HashableKey, ProveRequest, Prover, ProvingKey, SP1ProofMode, env::EnvProver};
use tokio::{
    runtime::{Handle, Runtime},
    task::block_in_place,
    time::sleep,
};
use zkaleido::{
    ExecutionSummary, ProgramId, ProofType, PublicValues, RemoteProofStatus, ZkVmError,
    ZkVmExecutor, ZkVmInputBuilder, ZkVmProver, ZkVmRemoteProver, ZkVmResult,
};

use crate::{SP1Host, input::SP1ProofInputBuilder, proof::SP1ProofReceipt};

impl ZkVmExecutor for SP1Host {
    type Input<'a> = SP1ProofInputBuilder;
    fn execute<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
    ) -> ZkVmResult<ExecutionSummary> {
        let elf = self.proving_key.elf().clone();
        let (output, report) = block_on_async(self.client.execute(elf, prover_input).into_future())
            .map_err(|e| ZkVmError::ExecutionError(e.to_string()))?;

        if self.config.require_success {
            ensure_clean_exit(&report)?;
        }

        let public_values = PublicValues::new(output.to_vec());

        Ok(ExecutionSummary::new(
            public_values,
            report.total_instruction_count(),
            report.gas(),
        ))
    }

    fn get_elf(&self) -> &[u8] {
        self.proving_key.elf()
    }

    fn save_trace(&self, trace_name: &str) {
        let profiling_file_name = format!("{}_{:?}.trace_profile", trace_name, &self);
        // SAFETY: SP1 consumes this process-global trace setting from the
        // environment. Callers must configure tracing before concurrent prover
        // work starts.
        unsafe {
            set_var("TRACE_FILE", profiling_file_name);
        }
    }

    fn program_id(&self) -> ProgramId {
        ProgramId(program_id_from_vk_hex(&self.proving_key.verifying_key().bytes32()))
    }
}

impl ZkVmProver for SP1Host {
    type ZkVmProofReceipt = SP1ProofReceipt;
    fn prove_inner<'a>(
        &self,
        prover_input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<SP1ProofReceipt> {
        if matches!(self.client, EnvProver::Network(_)) {
            return block_on_async(self.prove_via_network(prover_input, proof_type));
        }

        // Pre-flight: the local CPU prover would happily produce a proof
        // whose public values carry exit_code=1 (verifiable as panicked
        // by a downstream verifier). Fail fast with the same honest
        // ExecutionError the network path produces.
        <Self as ZkVmExecutor>::execute(self, prover_input.clone())?;

        let mode = to_sp1_mode(proof_type);
        let proof_info = block_on_async(async {
            self.client
                .prove(&self.proving_key, prover_input)
                .mode(mode)
                .await
        })
        .map_err(|e| ZkVmError::ProofGenerationError(e.to_string()))?;

        Ok(SP1ProofReceipt::new(proof_info, self.program_id()))
    }
}

impl SP1Host {
    /// Drives the async [`ZkVmRemoteProver`] methods (`start_proving` →
    /// poll `get_status` → `get_proof`) to produce an [`SP1ProofReceipt`].
    ///
    /// Used as the synchronous network proving path so that callers can invoke
    /// [`ZkVmProver::prove`] without choosing between the SP1 SDK's `blocking`
    /// API (which panics inside an existing tokio runtime) and the async API
    /// (which requires propagating `async` through every caller).
    async fn prove_via_network<'a>(
        &self,
        input: <<Self as ZkVmExecutor>::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
    ) -> ZkVmResult<SP1ProofReceipt> {
        let id = self.start_proving(input, proof_type).await?;
        loop {
            match self.get_status(&id).await? {
                RemoteProofStatus::Completed => break,
                RemoteProofStatus::Failed(reason) => {
                    return Err(ZkVmError::ProofGenerationError(reason.to_string()));
                }
                RemoteProofStatus::Requested | RemoteProofStatus::InProgress => {
                    sleep(self.config.network_poll_interval).await;
                }
            }
        }
        self.get_proof(&id)
            .await?
            .try_into()
            .map_err(ZkVmError::InvalidProofReceipt)
    }
}

pub(crate) fn to_sp1_mode(proof_type: ProofType) -> SP1ProofMode {
    match proof_type {
        ProofType::Compressed => SP1ProofMode::Compressed,
        ProofType::Core => SP1ProofMode::Core,
        ProofType::Groth16 => SP1ProofMode::Groth16,
    }
}

fn program_id_from_vk_hex(bytes32: &str) -> [u8; 32] {
    let hex = bytes32
        .strip_prefix("0x")
        .expect("SP1 bytes32 hash should be 0x-prefixed");
    <[u8; 32]>::from_hex(hex).expect("SP1 bytes32 hash should decode into 32 raw bytes")
}

/// Drives `future` to completion from a synchronous context, regardless of
/// whether the caller is already inside a tokio runtime.
///
/// Inside an existing multi-thread runtime, uses
/// [`tokio::task::block_in_place`] + [`Handle::block_on`] to avoid the nested
/// runtime panic produced by the SP1 SDK's `blocking` feature. Outside any
/// runtime, builds a fresh [`Runtime`] for this call.
///
/// **Caveat:** `block_in_place` requires a multi-thread runtime. Callers
/// running `current_thread` tokio runtimes should invoke the
/// [`ZkVmRemoteProver`] methods directly instead of going through sync
/// [`ZkVmProver::prove`].
pub(crate) fn block_on_async<F>(future: F) -> F::Output
where
    F: Future,
{
    match Handle::try_current() {
        Ok(handle) => block_in_place(|| handle.block_on(future)),
        Err(_) => {
            let rt = Runtime::new().expect("failed to build tokio runtime for sp1 prove");
            rt.block_on(future)
        }
    }
}

/// Converts an [`ExecutionReport`] with a non-zero `exit_code` into
/// [`ZkVmError::ExecutionError`].
///
/// The SP1 executor returns `Ok((pv, report))` even when the guest halted
/// with a non-zero exit code (panic). Without this check, a panicking
/// guest looks like a successful simulation — and the SDK's network
/// simulation path makes the same mistake, which is how a request the
/// guest will panic on can reach the network. SP1's
/// `SP1Context::expected_exit_code` does not help: that field is only
/// consulted by the verifier, never by the executor.
///
/// The cycle count is included in the message so operators can correlate
/// against the `panicked at ...` line the guest's panic handler prints
/// to stderr — the panic string itself isn't carried in
/// [`ExecutionReport`] (no panic-message field exists in SP1 6.2).
pub(crate) fn ensure_clean_exit(report: &ExecutionReport) -> ZkVmResult<()> {
    if report.exit_code != 0 {
        return Err(ZkVmError::ExecutionError(format!(
            "guest exited with non-zero exit code {} after {} instructions",
            report.exit_code,
            report.total_instruction_count(),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_clean_exit_rejects_non_zero_exit_code() {
        let mut report = ExecutionReport::default();
        report.exit_code = 1;
        let err = ensure_clean_exit(&report).expect_err("non-zero exit must error");
        match err {
            ZkVmError::ExecutionError(msg) => {
                assert!(msg.contains("exit code 1"), "got: {msg}");
                assert!(msg.contains("instructions"), "got: {msg}");
            }
            other => panic!("expected ExecutionError, got {other:?}"),
        }
    }

    #[test]
    fn ensure_clean_exit_accepts_success() {
        // Default ExecutionReport has exit_code = 0.
        assert!(ensure_clean_exit(&ExecutionReport::default()).is_ok());
    }

    #[test]
    fn program_id_from_vk_hex_decodes_32_bytes() {
        let program_id = program_id_from_vk_hex(
            "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        assert_eq!(
            program_id,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            ]
        );
    }
}
