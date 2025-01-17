use schnorr::{SchnorrSigInput, SchnorrSigProver};
use strata_zkvm::{ProofReceipt, ProofReport, ZkVmHost, ZkVmHostPerf, ZkVmProver, ZkVmProverPerf};

fn perf_report(host: &impl ZkVmHostPerf) -> ProofReport {
    let input = SchnorrSigInput::new_random();
    let report_name = "schnorr".to_string();
    SchnorrSigProver::perf_report(&input, host, report_name).unwrap()
}

#[cfg(feature = "sp1")]
fn sp1_proof_report() -> ProofReport {
    use strata_sp1_adapter::SP1Host;
    use strata_sp1_artifacts::SCHNORR_ELF;
    let host = SP1Host::init(&SCHNORR_ELF);
    perf_report(&host)
}

pub fn make_proofs() {
    #[cfg(feature = "sp1")]
    let report = sp1_proof_report();
    println!("{}", report.cycles);
}
