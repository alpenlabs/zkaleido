use schnorr_sig_verify::{SchnorrSigInput, SchnorrSigProver};
use zkaleido::{ProofReport, ZkVmHost, ZkVmProver};

fn perf_report(host: &impl ZkVmHost) -> ProofReport {
    let input = SchnorrSigInput::new_random();
    SchnorrSigProver::perf_report(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_schnorr_sig_verify_report() -> ProofReport {
    use strata_sp1_artifacts::SCHNORR_SIG_VERIFY_ELF;
    use zkaleido_sp1_adapter::SP1Host;
    let host = SP1Host::init(SCHNORR_SIG_VERIFY_ELF);
    perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_schnorr_sig_verify_report() -> ProofReport {
    use strata_risc0_artifacts::GUEST_RISC0_SCHNORR_SIG_VERIFY_ELF;
    use zkaleido_risc0_adapter::Risc0Host;
    let host = Risc0Host::init(GUEST_RISC0_SCHNORR_SIG_VERIFY_ELF);
    perf_report(&host)
}
