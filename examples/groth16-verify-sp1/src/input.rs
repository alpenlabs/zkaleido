use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zkaleido::{ProofReceipt, ProofReceiptWithMetadata};
use zkaleido_sp1_groth16_verifier::SP1Groth16Verifier;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SP1Groth16VerifyInput {
    pub sp1_receipt: ProofReceipt,
    pub sp1_verifier: SP1Groth16Verifier,
}

impl SP1Groth16VerifyInput {
    pub fn load() -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        let sp1_program_vk_hex = "0000e3572a33647cba427acbaecac23a01e237a8140d2c91b3873457beb5be13";
        let sp1_program_vk: [u8; 32] = hex::decode(sp1_program_vk_hex).unwrap().try_into().unwrap();

        let sp1_vk_bytes = include_bytes!("../vk/sp1_groth16_vk.bin");
        let sp1_verifier = SP1Groth16Verifier::load(sp1_vk_bytes, sp1_program_vk).unwrap();

        let sp1_proof_file = base.join(format!(
            "../../adapters/sp1/groth16-verifier/proofs/fibonacci_sp1_0x{}.proof.bin",
            sp1_program_vk_hex
        ));
        let sp1_receipt = ProofReceiptWithMetadata::load(sp1_proof_file)
            .unwrap()
            .receipt()
            .clone();

        SP1Groth16VerifyInput {
            sp1_receipt,
            sp1_verifier,
        }
    }
}
