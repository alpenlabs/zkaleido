use zkaleido::ZkVmEnv;

use crate::input::SP1Groth16VerifyInput;

pub mod input;
pub mod program;

pub fn process_groth16_verify_sp1(zkvm: &impl ZkVmEnv) {
    let SP1Groth16VerifyInput {
        sp1_receipt,
        sp1_verifier,
    } = zkvm.read_serde();

    let sp1_verified = sp1_verifier
        .verify(
            sp1_receipt.proof().as_bytes(),
            sp1_receipt.public_values().as_bytes(),
        )
        .is_ok();

    zkvm.commit_serde(&sp1_verified);
}
