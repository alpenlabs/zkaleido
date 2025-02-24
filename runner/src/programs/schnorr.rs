use schnorr_sig_verify::{SchnorrSigInput, SchnorrSigProgram};
use zkaleido::{PerformanceReport, ZkVmHostPerf, ZkVmProgramPerf};

fn perf_report(host: &impl ZkVmHostPerf) -> PerformanceReport {
    let input = SchnorrSigInput::new_random();
    SchnorrSigProgram::perf_report(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_schnorr_sig_verify_report() -> PerformanceReport {
    use zkaleido_sp1_adapter::SP1Host;
    use zkaleido_sp1_artifacts::SCHNORR_SIG_VERIFY_ELF;
    let host = SP1Host::init(SCHNORR_SIG_VERIFY_ELF);
    perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_schnorr_sig_verify_report() -> PerformanceReport {
    use zkaleido_risc0_adapter::Risc0Host;
    use zkaleido_risc0_artifacts::GUEST_RISC0_SCHNORR_SIG_VERIFY_ELF;
    let host = Risc0Host::init(GUEST_RISC0_SCHNORR_SIG_VERIFY_ELF);
    perf_report(&host)
}
