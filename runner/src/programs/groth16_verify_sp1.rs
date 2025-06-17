use groth16_verify_sp1::{input::SP1Groth16VerifyInput, program::SP1Groth16VerifyProgram};
use zkaleido::{PerformanceReport, ZkVmHostPerf, ZkVmProgramPerf};

fn perf_report(host: &impl ZkVmHostPerf) -> PerformanceReport {
    let input = SP1Groth16VerifyInput::load();
    SP1Groth16VerifyProgram::perf_report(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_groth16_verify() -> PerformanceReport {
    use zkaleido_sp1_artifacts::GROTH16_VERIFY_SP1_ELF;
    use zkaleido_sp1_host::SP1Host;
    let host = SP1Host::init(GROTH16_VERIFY_SP1_ELF);
    perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_groth16_verify() -> PerformanceReport {
    use zkaleido_risc0_artifacts::GUEST_RISC0_GROTH16_VERIFY_SP1_ELF;
    use zkaleido_risc0_host::Risc0Host;
    let host = Risc0Host::init(GUEST_RISC0_GROTH16_VERIFY_SP1_ELF);
    perf_report(&host)
}
