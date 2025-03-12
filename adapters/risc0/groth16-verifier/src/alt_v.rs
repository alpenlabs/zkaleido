//! # zkaleido-risc0-groth16-verifier
//!
//! This crate integrates RISC Zero-based Groth16 proof verification based on zkaleido traits.

use risc0_binfmt::tagged_struct;
use risc0_circuit_recursion::control_id::{ALLOWED_CONTROL_ROOT, BN254_IDENTITY_CONTROL_ID};
use risc0_groth16::{fr_from_hex_string, split_digest, verifying_key, Seal, Verifier};
use risc0_zkp::core::{
    digest::Digest,
    hash::sha::{Impl as Sha256Impl, Sha256},
};
use zkaleido::{DataFormatError, ProofReceipt, ZkVmError, ZkVmProofError, ZkVmResult};

pub fn compute_claim_digest<S: Sha256>(image_id: Digest, journal: Digest) -> Digest {
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

/// Verifies a RISC0-based Groth16 proof, using a 32-byte verification key.
///
/// This function checks whether the given [`ProofReceipt`] satisfies the constraints represented by
/// the provided `verification_key`. If successful, it returns an empty `Ok(())`; otherwise,
/// it returns a suitable [`ZkVmError`](zkaleido::ZkVmError).
pub fn verify_groth16_alt(receipt: &ProofReceipt, verification_key: &[u8; 32]) -> ZkVmResult<()> {
    let vk = verifying_key();
    let seal = Seal::from_vec(receipt.proof().as_bytes()).unwrap();

    let (a0, a1) = split_digest(ALLOWED_CONTROL_ROOT).map_err(|e| {
        ZkVmError::InvalidProofReceipt(ZkVmProofError::DataFormat(DataFormatError::Other(format!(
            "Invalid Control Root: {}",
            e
        ))))
    })?;

    let public_params_hash = *Sha256Impl::hash_bytes(receipt.public_values().as_bytes()).as_ref();
    let image_id = risc0_zkvm::sha::Digest::from_bytes(*verification_key);

    let claim_digest = compute_claim_digest::<Sha256Impl>(image_id, public_params_hash);

    let (c0, c1) = split_digest(claim_digest).map_err(|e| {
        ZkVmError::InvalidProofReceipt(ZkVmProofError::DataFormat(DataFormatError::Other(format!(
            "Invalid Public Params: {}",
            e
        ))))
    })?;

    let mut id_bn554 = BN254_IDENTITY_CONTROL_ID;
    id_bn554.as_mut_bytes().reverse();
    let id_bn254_fr = fr_from_hex_string(&hex::encode(id_bn554)).map_err(|e| {
        ZkVmError::InvalidProofReceipt(ZkVmProofError::DataFormat(DataFormatError::Other(format!(
            "Invalid BN254 Root: {}",
            e
        ))))
    })?;

    let verifier = Verifier::new(&seal, &[a0, a1, c0, c1, id_bn254_fr], &vk).unwrap();

    verifier
        .verify()
        .map_err(|e| zkaleido::ZkVmError::ProofVerificationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use zkaleido::ProofReceipt;

    use super::*;

    #[test]
    fn test_groth16_verification_alt() {
        let vk_hex = "0963493f27db6efac281ea2900ff4c611a93703cb9109dbd2231484121d08384";
        let vk: [u8; 32] = hex::decode(vk_hex).unwrap().try_into().unwrap();
        let proof_file = format!("./proofs/fibonacci_risc0_{}.proof.bin", vk_hex);

        let receipt = ProofReceipt::load(proof_file).unwrap();
        let res = verify_groth16_alt(&receipt, &vk);
        assert!(res.is_ok(), "groth16 proof verification must succeed");
    }
}
