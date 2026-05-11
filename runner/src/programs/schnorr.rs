use schnorr_sig_verify::{input::SchnorrSigInput, program::SchnorrSigProgram};
use zkaleido::{ExecutionSummary, ZkVmHost, ZkVmProgram};

fn execution_report(host: &impl ZkVmHost) -> (String, ExecutionSummary) {
    let input = SchnorrSigInput::new_random();
    let summary = SchnorrSigProgram::execute(&input, host).unwrap();
    (SchnorrSigProgram::name(), summary)
}

#[cfg(feature = "sp1")]
pub async fn sp1_schnorr_sig_verify_report() -> (String, ExecutionSummary) {
    use zkaleido_sp1_artifacts::SCHNORR_SIG_VERIFY_ELF;
    use zkaleido_sp1_host::SP1Host;
    let host = SP1Host::init(&SCHNORR_SIG_VERIFY_ELF).await;
    execution_report(&host)
}

#[cfg(feature = "risc0")]
pub async fn risc0_schnorr_sig_verify_report() -> (String, ExecutionSummary) {
    use zkaleido_risc0_artifacts::GUEST_RISC0_SCHNORR_SIG_VERIFY_ELF;
    use zkaleido_risc0_host::Risc0Host;
    let host = Risc0Host::init(GUEST_RISC0_SCHNORR_SIG_VERIFY_ELF);
    execution_report(&host)
}
