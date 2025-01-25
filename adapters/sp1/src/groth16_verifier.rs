use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
use strata_zkvm::{ProofReceipt, ZkVmError, ZkVmResult};

pub fn verify_groth16(receipt: &ProofReceipt, vkey_hash: &[u8; 32]) -> ZkVmResult<()> {
    let vk_hash_str = hex::encode(vkey_hash);
    let vk_hash_str = format!("0x{}", vk_hash_str);

    // TODO: optimization
    // Groth16Verifier internally again decodes the hex encoded vkey_hash, which can be avoided
    // Skipped for now because `load_groth16_proof_from_bytes` is not available outside of the
    // crate
    Groth16Verifier::verify(
        receipt.proof().as_bytes(),
        receipt.public_values().as_bytes(),
        &vk_hash_str,
        &GROTH16_VK_BYTES,
    )
    .map_err(|e| ZkVmError::ProofVerificationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use strata_zkvm::ProofReceipt;

    use crate::verify_groth16;

    #[test]
    fn test_groth16_verification() {
        let vk_hex = "00bf077c28baa685b0a9ec0b8d47eb51bc98f5c048f5aa386ea156fe24995a35";
        let vk: [u8; 32] = hex::decode(vk_hex).unwrap().try_into().unwrap();
        let proof_file = format!("./proofs/fibonacci_sp1_0x{}.proof.bin", vk_hex);

        let receipt = ProofReceipt::load(proof_file).unwrap();
        let res = verify_groth16(&receipt, &vk);
        assert!(res.is_ok(), "groth16 proof verification must succeed");
    }
}
