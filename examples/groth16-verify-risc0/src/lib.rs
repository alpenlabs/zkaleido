use zkaleido::ZkVmEnv;

use crate::input::Risc0Groth16VerifyInput;

pub mod input;
pub mod program;

pub fn process_groth16_verify_risc0(zkvm: &impl ZkVmEnv) {
    let Risc0Groth16VerifyInput {
        risc0_receipt,
        risc0_vk,
    } = zkvm.read_serde();

    let risc0_verified =
        zkaleido_risc0_groth16_verifier::verify_groth16(&risc0_receipt, &risc0_vk).is_ok();

    zkvm.commit_serde(&risc0_verified);
}
