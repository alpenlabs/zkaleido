use fibonacci::FibProgram;
use zkaleido::{PerformanceReport, ZkVmHostPerf, ZkVmProgramPerf};

fn fib_prover_perf_report(host: &impl ZkVmHostPerf) -> PerformanceReport {
    let input = 5;
    FibProgram::perf_report(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_fib_report() -> PerformanceReport {
    use zkaleido_sp1_artifacts::FIBONACCI_ELF;
    use zkaleido_sp1_host::SP1Host;
    let host = SP1Host::init(FIBONACCI_ELF);
    fib_prover_perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_fib_report() -> PerformanceReport {
    use zkaleido_risc0_artifacts::GUEST_RISC0_FIBONACCI_ELF;
    use zkaleido_risc0_host::Risc0Host;
    let host = Risc0Host::init(GUEST_RISC0_FIBONACCI_ELF);
    fib_prover_perf_report(&host)
}
