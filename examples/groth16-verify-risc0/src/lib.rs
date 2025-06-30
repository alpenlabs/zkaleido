use zkaleido::ZkVmEnv;

use crate::input::Risc0Groth16VerifyInput;

pub mod input;
pub mod program;

pub fn process_groth16_verify_risc0(zkvm: &impl ZkVmEnv) {
    let Risc0Groth16VerifyInput {
        risc0_receipt,
        risc0_verifier,
    } = zkvm.read_serde();

    let risc0_verified = risc0_verifier
        .verify(
            risc0_receipt.proof().as_bytes(),
            risc0_receipt.public_values().as_bytes(),
        )
        .is_ok();

    zkvm.commit_serde(&risc0_verified);
}
