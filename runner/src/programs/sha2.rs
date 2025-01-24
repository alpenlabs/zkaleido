use sha2_chain::ShaChainProver;
use strata_zkvm::{ProofReport, ZkVmHostPerf, ZkVmProver, ZkVmProverPerf};

fn sha2_prover_perf_report(host: &impl ZkVmHostPerf) -> ProofReport {
    let input = 5;
    ShaChainProver::prove(&input, host).unwrap();
    ShaChainProver::perf_report(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_sha_report() -> ProofReport {
    use strata_sp1_adapter::SP1Host;
    use strata_sp1_artifacts::SHA2_CHAIN_ELF;
    let host = SP1Host::init(SHA2_CHAIN_ELF);

    sha2_prover_perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_sha_report() -> ProofReport {
    use strata_risc0_adapter::Risc0Host;
    use strata_risc0_artifacts::GUEST_RISC0_SHA2_CHAIN_ELF;
    let host = Risc0Host::init(GUEST_RISC0_SHA2_CHAIN_ELF);
    sha2_prover_perf_report(&host)
}
