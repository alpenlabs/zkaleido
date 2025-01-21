use fibonacci::FibProver;
use strata_zkvm::{ProofReport, ZkVmHostPerf, ZkVmProverPerf};

fn fib_prover_perf_report(host: &impl ZkVmHostPerf) -> ProofReport {
    let input = 5;
    let report_name = "fibonacci".to_string();
    FibProver::perf_report(&input, host, report_name).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_fib_report() -> ProofReport {
    use strata_sp1_adapter::SP1Host;
    use strata_sp1_artifacts::FIBONACCI_ELF;
    let host = SP1Host::init(&FIBONACCI_ELF);
    fib_prover_perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_fib_report() -> ProofReport {
    use strata_risc0_adapter::Risc0Host;
    use strata_risc0_artifacts::GUEST_RISC0_FIBONACCI_ELF;
    let host = Risc0Host::init(&GUEST_RISC0_FIBONACCI_ELF);
    fib_prover_perf_report(&host)
}

#[allow(dead_code)]
pub fn make_proofs() {
    #[cfg(feature = "risc0")]
    let _ = risc0_fib_report();

    #[cfg(feature = "sp1")]
    let _ = sp1_fib_report();
}
