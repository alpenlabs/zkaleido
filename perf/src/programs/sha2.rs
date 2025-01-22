use sha2_chain::ShaChainProver;
use strata_zkvm::{ProofReport, ZkVmHostPerf, ZkVmProverPerf};

fn sha2_prover_perf_report(host: &impl ZkVmHostPerf) -> ProofReport {
    let input = 5;
    let report_name = "sha2".to_string();
    ShaChainProver::perf_report(&input, host, report_name).unwrap()
}

#[cfg(any(
    all(feature = "sp1", not(feature = "sp1-mock")),
    all(feature = "risc0", not(feature = "risc0-mock"))
))]
fn sha2_proof(host: &impl ZkVmHost) -> ProofReceipt {
    use strata_zkvm::{ProofReceipt, ZkVmHost, ZkVmProver};
    let input = 5;
    ShaChainProver::prove(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_sha_report() -> ProofReport {
    use strata_sp1_adapter::SP1Host;
    use strata_sp1_artifacts::SHA2_CHAIN_ELF;
    let host = SP1Host::init(SHA2_CHAIN_ELF);

    #[cfg(not(feature = "sp1-mock"))]
    {
        let proof = sha2_proof(&host);
        proof.save("sha2.sp1.proof").unwrap();
    }
    sha2_prover_perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_sha_report() -> ProofReport {
    use strata_risc0_adapter::Risc0Host;
    use strata_risc0_artifacts::GUEST_RISC0_SHA2_CHAIN_ELF;
    let host = Risc0Host::init(GUEST_RISC0_SHA2_CHAIN_ELF);
    #[cfg(not(feature = "risc0-mock"))]
    {
        let proof = sha2_proof(&host);
        proof.save("sha2.risc0.proof").unwrap();
    }
    sha2_prover_perf_report(&host)
}
