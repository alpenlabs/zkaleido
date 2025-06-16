use zkaleido::ZkVmEnv;
use zkaleido_sp1_groth16_verifier::SP1Groth16Verifier;

use crate::input::SP1Groth16VerifyInput;

pub mod input;
pub mod program;

pub fn process_groth16_verify_sp1(zkvm: &impl ZkVmEnv) {
    let SP1Groth16VerifyInput {
        sp1_receipt,
        sp1_vk,
    } = zkvm.read_serde();

    let sp1_verifier =
        SP1Groth16Verifier::load(include_bytes!("../vk/sp1_groth16_vk.bin"), sp1_vk).unwrap();
    let sp1_verified = sp1_verifier
        .verify(
            sp1_receipt.proof().as_bytes(),
            sp1_receipt.public_values().as_bytes(),
        )
        .is_ok();

    zkvm.commit_serde(&sp1_verified);
}
