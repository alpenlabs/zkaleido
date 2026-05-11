use groth16_verify_sp1::{input::SP1Groth16VerifyInput, program::SP1Groth16VerifyProgram};
use zkaleido::{ExecutionSummary, ZkVmHost, ZkVmProgram};

fn execution_report(host: &impl ZkVmHost) -> (String, ExecutionSummary) {
    let input = SP1Groth16VerifyInput::load();
    let summary = SP1Groth16VerifyProgram::execute(&input, host).unwrap();
    (SP1Groth16VerifyProgram::name(), summary)
}

#[cfg(feature = "sp1")]
pub async fn sp1_groth16_verify() -> (String, ExecutionSummary) {
    use zkaleido_sp1_artifacts::GROTH16_VERIFY_SP1_ELF;
    use zkaleido_sp1_host::SP1Host;
    let host = SP1Host::init(&GROTH16_VERIFY_SP1_ELF).await;
    execution_report(&host)
}

#[cfg(feature = "risc0")]
pub async fn risc0_groth16_verify() -> (String, ExecutionSummary) {
    use zkaleido_risc0_artifacts::GUEST_RISC0_GROTH16_VERIFY_SP1_ELF;
    use zkaleido_risc0_host::Risc0Host;
    let host = Risc0Host::init(GUEST_RISC0_GROTH16_VERIFY_SP1_ELF);
    execution_report(&host)
}
