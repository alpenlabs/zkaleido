use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zkaleido::ProofReceipt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SP1Groth16VerifyInput {
    pub sp1_receipt: ProofReceipt,
    pub sp1_vk: [u8; 32],
}

impl SP1Groth16VerifyInput {
    pub fn load() -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        let sp1_vk_hex = "0000e3572a33647cba427acbaecac23a01e237a8140d2c91b3873457beb5be13";
        let sp1_vk: [u8; 32] = hex::decode(sp1_vk_hex).unwrap().try_into().unwrap();
        let sp1_proof_file = base.join(format!(
            "../../adapters/sp1/groth16-verifier/proofs/fibonacci_sp1_0x{}.proof.bin",
            sp1_vk_hex
        ));
        let sp1_receipt = ProofReceipt::load(sp1_proof_file).unwrap();

        SP1Groth16VerifyInput {
            sp1_receipt,
            sp1_vk,
        }
    }
}
