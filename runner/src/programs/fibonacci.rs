use fibonacci::FibProver;
use strata_zkvm::{ProofReceipt, ZkVmHost, ZkVmProver};

fn prove(host: &impl ZkVmHost) -> ProofReceipt {
    let input = 5;
    FibProver::prove(&input, host).unwrap()
}

#[cfg(feature = "sp1")]
fn sp1_prove() -> ProofReceipt {
    use strata_sp1_adapter::SP1Host;
    use strata_sp1_artifacts::{
        GUEST_SP1_FIBONACCI_ELF, GUEST_SP1_FIBONACCI_PK, GUEST_SP1_FIBONACCI_VK,
    };
    let host = SP1Host::new_from_bytes(
        &GUEST_SP1_FIBONACCI_ELF,
        &GUEST_SP1_FIBONACCI_PK,
        &GUEST_SP1_FIBONACCI_VK,
    );
    prove(&host)
}

#[cfg(feature = "risc0")]
fn risc0_prove() -> ProofReceipt {
    use strata_risc0_adapter::Risc0Host;

    use strata_risc0_artifacts::GUEST_RISC0_FIBONACCI_ELF;
    let host = Risc0Host::init(&GUEST_RISC0_FIBONACCI_ELF);
    prove(&host)
}

pub fn make_proofs() {
    // TODO: add reports
    #[cfg(feature = "risc0")]
    let _ = risc0_prove();

    #[cfg(feature = "sp1")]
    let _ = sp1_prove();
}
