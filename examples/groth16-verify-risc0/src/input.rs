use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zkaleido::ProofReceipt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risc0Groth16VerifyInput {
    pub risc0_receipt: ProofReceipt,
    pub risc0_vk: [u8; 32],
}

impl Risc0Groth16VerifyInput {
    pub fn load() -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        let risc0_vk_hex = "25eaa741d5cb0d99fe15ce60c4bf3886f96932f22ee67041f0b4165203ef5a02";
        let risc0_vk: [u8; 32] = hex::decode(risc0_vk_hex).unwrap().try_into().unwrap();
        let proof_file = base.join(format!(
            "../../adapters/risc0/groth16-verifier/proofs/fibonacci_risc0_{}.proof.bin",
            risc0_vk_hex
        ));
        let risc0_receipt = ProofReceipt::load(proof_file).unwrap();

        Risc0Groth16VerifyInput {
            risc0_receipt,
            risc0_vk,
        }
    }
}
