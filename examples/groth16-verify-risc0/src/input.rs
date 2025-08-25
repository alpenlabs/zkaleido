use std::path::PathBuf;

use risc0_groth16::verifying_key;
use risc0_zkp::core::digest::{digest, Digest};
use serde::{Deserialize, Serialize};
use zkaleido::{ProofReceipt, ProofReceiptWithMetadata};
use zkaleido_risc0_groth16_verifier::Risc0Groth16Verifier;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risc0Groth16VerifyInput {
    pub risc0_receipt: ProofReceipt,
    pub risc0_verifier: Risc0Groth16Verifier,
}

impl Risc0Groth16VerifyInput {
    pub fn load() -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        let image_id_hex = "f4e0413eee665668164b02be80c63b5e71e387ae08b7f9e75e5983cf9eb9518a";
        let image_id: [u8; 32] = hex::decode(image_id_hex).unwrap().try_into().unwrap();
        let image_id = Digest::from_bytes(image_id);

        let proof_file = base.join(format!(
            "../../adapters/risc0/groth16-verifier/proofs/fibonacci_risc0_{}.proof.bin",
            image_id_hex
        ));
        let risc0_receipt = ProofReceiptWithMetadata::load(proof_file)
            .unwrap()
            .receipt()
            .clone();

        let vk = verifying_key();

        pub const ALLOWED_CONTROL_ROOT: Digest =
            digest!("a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56");

        pub const BN254_IDENTITY_CONTROL_ID: Digest =
            digest!("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404");

        let risc0_verifier = Risc0Groth16Verifier::new(
            vk,
            BN254_IDENTITY_CONTROL_ID,
            ALLOWED_CONTROL_ROOT,
            image_id,
        );

        Risc0Groth16VerifyInput {
            risc0_receipt,
            risc0_verifier,
        }
    }
}
