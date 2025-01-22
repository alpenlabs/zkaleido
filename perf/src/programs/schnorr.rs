use schnorr_sig_verify::{SchnorrSigInput, SchnorrSigProver};
use strata_zkvm::{ProofReport, ZkVmHostPerf, ZkVmProverPerf};

fn perf_report(host: &impl ZkVmHostPerf) -> ProofReport {
    let input = SchnorrSigInput::new_random();
    let report_name = "schnorr".to_string();
    SchnorrSigProver::perf_report(&input, host, report_name).unwrap()
}

#[cfg(any(
    all(feature = "sp1", not(feature = "sp1-mock")),
    all(feature = "risc0", not(feature = "risc0-mock"))
))]
fn schnorr_sig_verify_proof(host: &impl ZkVmHost) -> ProofReceipt {
    use strata_zkvm::{ProofReceipt, ZkVmHost, ZkVmProver};
    let input = SchnorrSigInput::new_random();
    SchnorrSigProver::prove(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_schnorr_sig_verify_report() -> ProofReport {
    use strata_sp1_adapter::SP1Host;
    use strata_sp1_artifacts::SCHNORR_SIG_VERIFY_ELF;
    let host = SP1Host::init(SCHNORR_SIG_VERIFY_ELF);
    #[cfg(not(feature = "sp1-mock"))]
    {
        let proof = fib_proof(&host);
        proof.save("schnorr.sp1.proof").unwrap();
    }
    perf_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_schnorr_sig_verify_report() -> ProofReport {
    use strata_risc0_adapter::Risc0Host;
    use strata_risc0_artifacts::GUEST_RISC0_SCHNORR_SIG_VERIFY_ELF;
    let host = Risc0Host::init(GUEST_RISC0_SCHNORR_SIG_VERIFY_ELF);
    #[cfg(not(feature = "risc0-mock"))]
    {
        let proof = sha2_proof(&host);
        proof.save("schnorr.risc0.proof").unwrap();
    }
    perf_report(&host)
}
