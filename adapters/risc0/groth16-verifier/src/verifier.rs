use risc0_binfmt::tagged_struct;
use risc0_groth16::{
    fr_from_hex_string, split_digest, verifying_key, Fr, Seal, Verifier, VerifyingKey,
};
use risc0_zkp::core::{
    digest::{digest, Digest},
    hash::sha::Sha256,
};
use serde::{Deserialize, Serialize};

use crate::sha256::Impl as Sha256Impl;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Risc0Groth16Verifier {
    vk: VerifyingKey,
    bn254_id: Fr,
    allowed_root: (Fr, Fr),
    image_id: Digest,
}

impl Risc0Groth16Verifier {
    pub fn load(
        vk: VerifyingKey,
        bn254_control_root: Digest,
        allowed_control_root: Digest,
        image_id: Digest,
    ) -> Self {
        let mut bn254_id = bn254_control_root;
        bn254_id.as_mut_bytes().reverse();

        let (a0, a1) = split_digest(allowed_control_root).unwrap();
        let bn254_id = fr_from_hex_string(&hex::encode(bn254_id)).unwrap();

        Self {
            vk,
            bn254_id,
            allowed_root: (a0, a1),
            image_id,
        }
    }

    pub fn verify(&self, proof: &[u8], public_values: &[u8]) -> bool {
        let seal = Seal::from_vec(proof).unwrap();

        let public_params_hash = *Sha256Impl::hash_bytes(public_values);
        let claim_digest = compute_claim_digest::<Sha256Impl>(self.image_id, public_params_hash);

        let (c0, c1) = split_digest(claim_digest).unwrap();
        let (a0, a1) = self.allowed_root.clone();
        let verifier =
            Verifier::new(&seal, &[a0, a1, c0, c1, self.bn254_id.clone()], &self.vk).unwrap(); // TODO:

        verifier.verify().unwrap();

        true
    }
}

/// Computes the digest of Claim without constructing the state
/// TODO: add more detail here
fn compute_claim_digest<S: Sha256>(image_id: Digest, journal: Digest) -> Digest {
    let post_digest = tagged_struct::<S>("risc0.SystemState", &[Digest::ZERO], &[0]);
    let (sys_exit, user_exit) = (0, 0);
    let input_digest = Digest::ZERO;
    let output_digest = tagged_struct::<S>("risc0.Output", &[journal, Digest::ZERO], &[]);
    tagged_struct::<S>(
        "risc0.ReceiptClaim",
        &[input_digest, image_id, post_digest, output_digest],
        &[sys_exit, user_exit],
    )
}

#[cfg(test)]
mod tests {
    use risc0_circuit_recursion::control_id::{ALLOWED_CONTROL_ROOT, BN254_IDENTITY_CONTROL_ID};
    use risc0_groth16::verifying_key;
    use risc0_zkvm::{Digest, ALLOWED_CONTROL_IDS};
    use zkaleido::ProofReceipt;

    use crate::verifier::Risc0Groth16Verifier;

    fn get_proof_and_image_id() -> (ProofReceipt, [u8; 32]) {
        let image_id_hex = "7f3599b6e5c45edc6c2dcd88a9df76d1c9fce38cfb2afc8e5615f154d878009b";
        let image_id: [u8; 32] = hex::decode(image_id_hex).unwrap().try_into().unwrap();
        let proof_file = format!("./proofs/fibonacci_risc0_{}.proof.bin", image_id_hex);

        let receipt = ProofReceipt::load(proof_file).unwrap();

        (receipt, image_id)
    }

    #[test]
    fn test_groth16_verification() {
        let (receipt, image_id) = get_proof_and_image_id();
        let vk = verifying_key();
        let risc0_verifier = Risc0Groth16Verifier::load(
            vk,
            BN254_IDENTITY_CONTROL_ID,
            ALLOWED_CONTROL_ROOT,
            Digest::from_bytes(image_id),
        );

        risc0_verifier.verify(
            receipt.proof().as_bytes(),
            receipt.public_values().as_bytes(),
        );
    }
}
