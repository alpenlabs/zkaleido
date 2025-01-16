use schnorr::{SchnorrSigInput, SchnorrSigProver};
use strata_zkvm::{ProofReceipt, ZkVmHost, ZkVmProver};

fn prove(host: &impl ZkVmHost) -> ProofReceipt {
    let input = SchnorrSigInput::new_random();
    SchnorrSigProver::prove(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
fn sp1_prove() -> ProofReceipt {
    use strata_sp1_adapter::SP1Host;
    use strata_sp1_artifacts::SCHNORR_ELF;
    let host = SP1Host::init(&SCHNORR_ELF);
    prove(&host)
}

pub fn make_proofs() {
    // TODO: add reports

    #[cfg(feature = "sp1")]
    let _ = sp1_prove();
}
