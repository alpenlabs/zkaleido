use schnorr_sig_verify::{SchnorrSigInput, SchnorrSigProver};
use strata_zkvm::{ProofReport, ZkVmHostPerf, ZkVmProver, ZkVmProverPerf};

fn perf_report(host: &impl ZkVmHostPerf) -> ProofReport {
    let input = SchnorrSigInput::new_random();
    let proof_file_name = format!("{}_{:?}.proof", SchnorrSigProver::name(), host);
    let proof = SchnorrSigProver::prove(&input, host).unwrap();
    proof.save(proof_file_name).unwrap();
    SchnorrSigProver::perf_report(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_schnorr_sig_verify_report() -> ProofReport {
    use strata_sp1_adapter::SP1Host;
    use strata_sp1_artifacts::SCHNORR_SIG_VERIFY_ELF;
    let host = SP1Host::init(SCHNORR_SIG_VERIFY_ELF);
    perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_schnorr_sig_verify_report() -> ProofReport {
    use strata_risc0_adapter::Risc0Host;
    use strata_risc0_artifacts::GUEST_RISC0_SCHNORR_SIG_VERIFY_ELF;
    let host = Risc0Host::init(GUEST_RISC0_SCHNORR_SIG_VERIFY_ELF);
    perf_report(&host)
}
