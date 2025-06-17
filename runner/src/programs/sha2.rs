use sha2_chain::program::ShaChainProgram;
use zkaleido::{PerformanceReport, ZkVmHostPerf, ZkVmProgramPerf};

fn sha2_prover_perf_report(host: &impl ZkVmHostPerf) -> PerformanceReport {
    let input = 5;
    ShaChainProgram::perf_report(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_sha_report() -> PerformanceReport {
    use zkaleido_sp1_artifacts::SHA2_CHAIN_ELF;
    use zkaleido_sp1_host::SP1Host;
    let host = SP1Host::init(SHA2_CHAIN_ELF);

    sha2_prover_perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_sha_report() -> PerformanceReport {
    use zkaleido_risc0_artifacts::GUEST_RISC0_SHA2_CHAIN_ELF;
    use zkaleido_risc0_host::Risc0Host;
    let host = Risc0Host::init(GUEST_RISC0_SHA2_CHAIN_ELF);
    sha2_prover_perf_report(&host)
}
