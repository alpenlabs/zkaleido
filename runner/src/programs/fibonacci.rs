use fibonacci::FibProver;
use zkaleido::{PerfReport, ZkVmHost, ZkVmProver};

fn fib_prover_perf_report(host: &impl ZkVmHost) -> PerfReport {
    let input = 5;
    FibProver::perf_report(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_fib_report() -> PerfReport {
    use zkaleido_sp1_adapter::SP1Host;
    use zkaleido_sp1_artifacts::FIBONACCI_ELF;
    let host = SP1Host::init(FIBONACCI_ELF);
    fib_prover_perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_fib_report() -> PerfReport {
    use zkaleido_risc0_adapter::Risc0Host;
    use zkaleido_risc0_artifacts::GUEST_RISC0_FIBONACCI_ELF;
    let host = Risc0Host::init(GUEST_RISC0_FIBONACCI_ELF);
    fib_prover_perf_report(&host)
}
