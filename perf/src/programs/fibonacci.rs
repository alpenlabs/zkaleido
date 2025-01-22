use fibonacci::FibProver;
#[cfg(any(
    all(feature = "sp1", not(feature = "sp1-mock")),
    all(feature = "risc0", not(feature = "risc0-mock"))
))]
use strata_zkvm::{ProofReceipt, ZkVmHost, ZkVmProver};
use strata_zkvm::{ProofReport, ZkVmHostPerf, ZkVmProverPerf};

fn fib_prover_perf_report(host: &impl ZkVmHostPerf) -> ProofReport {
    let input = 5;
    let report_name = "fibonacci".to_string();
    FibProver::perf_report(&input, host, report_name).unwrap()
}

#[cfg(any(
    all(feature = "sp1", not(feature = "sp1-mock")),
    all(feature = "risc0", not(feature = "risc0-mock"))
))]
fn fib_proof(host: &impl ZkVmHost) -> ProofReceipt {
    let input = 5;
    FibProver::prove(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_fib_report() -> ProofReport {
    use strata_sp1_adapter::SP1Host;
    use strata_sp1_artifacts::FIBONACCI_ELF;
    let host = SP1Host::init(FIBONACCI_ELF);
    #[cfg(not(feature = "sp1-mock"))]
    {
        let proof = fib_proof(&host);
        proof.save("fib.sp1.proof").unwrap();
    }
    fib_prover_perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_fib_report() -> ProofReport {
    use strata_risc0_adapter::Risc0Host;
    use strata_risc0_artifacts::GUEST_RISC0_FIBONACCI_ELF;
    let host = Risc0Host::init(GUEST_RISC0_FIBONACCI_ELF);
    #[cfg(not(feature = "risc0-mock"))]
    {
        let proof = fib_proof(&host);
        proof.save("fib.risc0.proof").unwrap();
    }
    fib_prover_perf_report(&host)
}
