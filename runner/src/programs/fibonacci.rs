use fibonacci::FibProver;
use strata_zkvm::{ProofReport, ZkVmHostPerf, ZkVmProver, ZkVmProverPerf};

fn fib_prover_perf_report(host: &impl ZkVmHostPerf) -> ProofReport {
    let input = 5;
    FibProver::prove(&input, host).unwrap();
    FibProver::perf_report(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_fib_report() -> ProofReport {
    use strata_sp1_adapter::SP1Host;
    use strata_sp1_artifacts::FIBONACCI_ELF;
    let host = SP1Host::init(FIBONACCI_ELF);
    fib_prover_perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_fib_report() -> ProofReport {
    use strata_risc0_adapter::Risc0Host;
    use strata_risc0_artifacts::GUEST_RISC0_FIBONACCI_ELF;
    let host = Risc0Host::init(GUEST_RISC0_FIBONACCI_ELF);
    fib_prover_perf_report(&host)
}
