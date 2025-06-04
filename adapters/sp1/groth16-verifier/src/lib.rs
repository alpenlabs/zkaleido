//! # zkaleido-sp1-groth16-verifier
//!
//! This crate integrates SP1-based Groth16 proof verification based on zkaleido traits.

use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
use zkaleido::{ProofReceipt, ZkVmError, ZkVmResult};

use crate::verify::SP1Groth16Verifier;

mod constants;
mod converter;
mod error;
mod types;
mod utils;
mod verify;

/// Verifies a SP1-based Groth16 proof, using a 32-byte verification key.
///
/// This function checks whether the given [`ProofReceipt`] satisfies the constraints represented by
/// the provided `verification_key`. If successful, it returns an empty `Ok(())`; otherwise,
/// it returns a suitable [`ZkVmError`].
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

/// Verifies a SP1-based Groth16 proof, using a 32-byte verification key.
///
/// This function checks whether the given [`ProofReceipt`] satisfies the constraints represented by
/// the provided `verification_key`. If successful, it returns an empty `Ok(())`; otherwise,
/// it returns a suitable [`ZkVmError`].
pub fn verify_groth16_alt(receipt: &ProofReceipt, vkey_hash: &[u8; 32]) -> ZkVmResult<()> {
    SP1Groth16Verifier::verify(
        receipt.proof().as_bytes(),
        receipt.public_values().as_bytes(),
        *vkey_hash,
        &GROTH16_VK_BYTES,
    )
    .map_err(|e| ZkVmError::ProofVerificationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use zkaleido::ProofReceipt;

    use crate::{verify_groth16, verify_groth16_alt};

    #[test]
    fn test_groth16_verification() {
        let vk_hex = "0000e3572a33647cba427acbaecac23a01e237a8140d2c91b3873457beb5be13";
        let vk: [u8; 32] = hex::decode(vk_hex).unwrap().try_into().unwrap();
        let proof_file = format!("./proofs/fibonacci_sp1_0x{}.proof.bin", vk_hex);

        let receipt = ProofReceipt::load(proof_file).unwrap();
        let res = verify_groth16(&receipt, &vk);
        assert!(res.is_ok(), "groth16 proof verification must succeed");
    }

    #[test]
    fn test_groth16_verification_alt() {
        let vk_hex = "0000e3572a33647cba427acbaecac23a01e237a8140d2c91b3873457beb5be13";
        let vk: [u8; 32] = hex::decode(vk_hex).unwrap().try_into().unwrap();
        let proof_file = format!("./proofs/fibonacci_sp1_0x{}.proof.bin", vk_hex);

        let receipt = ProofReceipt::load(proof_file).unwrap();
        let res = verify_groth16_alt(&receipt, &vk);
        assert!(res.is_ok(), "groth16 proof verification must succeed");
    }
}
