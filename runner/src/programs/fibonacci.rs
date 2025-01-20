use fibonacci::FibProver;
use strata_zkvm::{ProofReport, ZkVmHostPerf, ZkVmProverPerf};

fn perf_report(host: &impl ZkVmHostPerf) -> ProofReport {
    let input = 5;
    let report_name = "fibonacci".to_string();
    FibProver::perf_report(&input, host, report_name).unwrap()
}

#[cfg(feature = "sp1")]
fn sp1_perf_report() -> ProofReport {
    use strata_sp1_adapter::SP1Host;
    use strata_sp1_artifacts::FIBONACCI_ELF;
    let host = SP1Host::init(&FIBONACCI_ELF);
    perf_report(&host)
}

#[cfg(feature = "risc0")]
fn risc0_perf_report() -> ProofReport {
    use strata_risc0_adapter::Risc0Host;
    use strata_risc0_artifacts::GUEST_RISC0_FIBONACCI_ELF;
    let host = Risc0Host::init(&GUEST_RISC0_FIBONACCI_ELF);
    perf_report(&host)
}

pub fn make_proofs() {
    #[cfg(feature = "risc0")]
    let _ = risc0_perf_report();

    #[cfg(feature = "sp1")]
    let _ = sp1_perf_report();
}
