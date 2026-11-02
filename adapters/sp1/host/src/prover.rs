use std::{
    env::set_var,
    future::{Future, IntoFuture},
};

use sp1_core_executor::{ExecutionError, ExecutionReport};
use sp1_sdk::{HashableKey, ProveRequest, Prover, ProvingKey, SP1ProofMode, env::EnvProver};
use tokio::{
    runtime::{Handle, Runtime},
    task::block_in_place,
    time::sleep,
};
use zkaleido::{
    ExecutionSummary, ProgramId, ProofType, PublicValues, RemoteProofStatus, ZkVmError,
    ZkVmExecutionError, ZkVmExecutor, ZkVmInputBuilder, ZkVmProver, ZkVmRemoteProver, ZkVmResult,
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
            .map_err(classify_execution_error)?;

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
        let profiling_file_name = format!("{}_{:?}.trace_profile", trace_name, self);
        // SAFETY: SP1 consumes this process-global trace setting from the
        // environment. Callers must configure tracing before concurrent prover
        // work starts.
        unsafe {
            set_var("TRACE_FILE", profiling_file_name);
        }
    }

    fn program_id(&self) -> ProgramId {
        ProgramId(self.proving_key.verifying_key().bytes32_raw())
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

/// Messages of the SP1 executor errors that are the guest's fault. Each one is
/// the fixed start of an [`ExecutionError`] variant's `Display` text, or of a
/// message SP1 builds around the guest ELF.
///
/// A failed run reaches us as [`ExecutionError::Other`] holding only the
/// message, because the SDK flattens the typed error with `to_string()` (see
/// `ExecuteRequest::into_future` in sp1-sdk). So the message is all we can
/// classify on. The tests pin this list against the real variants, so an SP1
/// bump that changes the wording fails them.
///
/// TODO: match on the typed variants once the SDK stops flattening its
/// execution errors. String matching breaks silently if SP1 rewords a message
/// the tests do not cover.
const GUEST_ERROR_PREFIXES: &[&str] = &[
    "invalid memory access for opcode ",
    "invalid memory access for untrusted program at address ",
    "unimplemented syscall ",
    "breakpoint encountered",
    "exceeded cycle limit of ",
    "syscall called in unconstrained mode",
    "got unimplemented as opcode",
    "program ended in unconstrained mode",
    "unconstrained cycle limit exceeded",
    "Unexpected exit code: ",
    "Instruction not found, page protect/ untrusted program set to off",
    "Trap occurred without proper handling",
    "SP1 program consumes too much memory",
    "failed to dissassemble program",
];

/// Converts an SP1 executor error into [`ZkVmError::ExecutionError`], deciding
/// whether the guest or the host is at fault.
///
/// Only errors that come from the program and its input count as guest
/// errors. Everything else is a host error, including executor crashes such as
/// the SIGBUS SP1's native executor raises when `/dev/shm` is full. Defaulting
/// to host means an unknown error gets retried rather than failing for good.
pub(crate) fn classify_execution_error(err: ExecutionError) -> ZkVmError {
    let msg = err.to_string();
    let err = if GUEST_ERROR_PREFIXES
        .iter()
        .any(|prefix| msg.starts_with(prefix))
    {
        ZkVmExecutionError::Guest(msg)
    } else {
        ZkVmExecutionError::Host(msg)
    };
    err.into()
}

/// Converts an [`ExecutionReport`] with a non-zero `exit_code` into a guest
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
        return Err(ZkVmExecutionError::Guest(format!(
            "guest exited with non-zero exit code {} after {} instructions",
            report.exit_code,
            report.total_instruction_count(),
        ))
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sp1_core_executor::{Opcode, TrapError};

    use super::*;

    fn is_guest(err: ExecutionError) -> bool {
        match classify_execution_error(err) {
            ZkVmError::ExecutionError(ZkVmExecutionError::Guest(_)) => true,
            ZkVmError::ExecutionError(ZkVmExecutionError::Host(_)) => false,
            other => panic!("expected ExecutionError, got {other:?}"),
        }
    }

    /// Checks both the typed variant and the flattened form the SDK hands us.
    fn assert_guest(err: ExecutionError) {
        let flattened = ExecutionError::Other(err.to_string());
        assert!(is_guest(err.clone()), "typed {err:?} must be guest");
        assert!(is_guest(flattened), "flattened {err:?} must be guest");
    }

    fn assert_host(err: ExecutionError) {
        let flattened = ExecutionError::Other(err.to_string());
        assert!(!is_guest(err.clone()), "typed {err:?} must be host");
        assert!(!is_guest(flattened), "flattened {err:?} must be host");
    }

    #[test]
    fn guest_faults_classify_as_guest() {
        assert_guest(ExecutionError::InvalidMemoryAccess(Opcode::LD, 0x10));
        assert_guest(ExecutionError::InvalidMemoryAccessUntrustedProgram(0x11));
        assert_guest(ExecutionError::UnsupportedSyscall(7));
        assert_guest(ExecutionError::Breakpoint());
        assert_guest(ExecutionError::ExceededCycleLimit(100));
        assert_guest(ExecutionError::InvalidSyscallUsage(3));
        assert_guest(ExecutionError::Unimplemented());
        assert_guest(ExecutionError::EndInUnconstrained());
        assert_guest(ExecutionError::UnconstrainedCycleLimitExceeded(100));
        assert_guest(ExecutionError::UnexpectedExitCode(1));
        assert_guest(ExecutionError::InstructionNotFound());
        assert_guest(ExecutionError::UnhandledTrap(
            TrapError::PagePermissionViolation(1),
        ));
        assert_guest(ExecutionError::TooMuchMemory());
        assert_guest(ExecutionError::Other(
            "failed to dissassemble program: bad elf".into(),
        ));
    }

    #[test]
    fn host_faults_classify_as_host() {
        assert_host(ExecutionError::KilledByMemoryMonitor(1024));
        assert_host(ExecutionError::ChildKilled());
        assert_host(ExecutionError::InvalidShardingState());
        // Messages SP1's native runner builds when the child executor dies.
        // The first is what a full /dev/shm (SIGBUS) produces.
        assert_host(ExecutionError::Other(
            "Child native executor terminated abnormally, code: None, signal: Some(7)".into(),
        ));
        assert_host(ExecutionError::Other(
            "Child native executor crashed, details: ...".into(),
        ));
        assert_host(ExecutionError::Other(
            "failed to spawn child process: No such file or directory".into(),
        ));
    }

    #[test]
    fn ensure_clean_exit_rejects_non_zero_exit_code() {
        let mut report = ExecutionReport::default();
        report.exit_code = 1;
        let err = ensure_clean_exit(&report).expect_err("non-zero exit must error");
        match err {
            ZkVmError::ExecutionError(ZkVmExecutionError::Guest(msg)) => {
                assert!(msg.contains("exit code 1"), "got: {msg}");
                assert!(msg.contains("instructions"), "got: {msg}");
            }
            other => panic!("expected guest ExecutionError, got {other:?}"),
        }
    }

    #[test]
    fn ensure_clean_exit_accepts_success() {
        // Default ExecutionReport has exit_code = 0.
        assert!(ensure_clean_exit(&ExecutionReport::default()).is_ok());
    }
}
