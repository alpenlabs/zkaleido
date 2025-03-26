//! # zkaleido-risc0-groth16-verifier
//!
//! This crate integrates RISC Zero-based Groth16 proof verification based on zkaleido traits.

use risc0_binfmt::tagged_struct;
use risc0_groth16::{fr_from_hex_string, split_digest, verifying_key, Seal, Verifier};
use risc0_zkp::core::{
    digest::{digest, Digest},
    hash::sha::{Impl as Sha256Impl, Sha256},
};
use zkaleido::{DataFormatError, ProofReceipt, ZkVmError, ZkVmProofError, ZkVmResult};

/// Root of the Merkle tree constructed from [ALLOWED_CONTROL_IDS](https://github.com/risc0/risc0/blob/main/risc0/circuit/recursion/src/control_id.rs#L23-L37), using Poseidon2.
pub const ALLOWED_CONTROL_ROOT: Digest =
    digest!("539032186827b06719244873b17b2d4c122e2d02cfb1994fe958b2523b844576");

/// Control ID for the identity recursion programs (ZKR), using Poseidon over the BN254 scalar
/// field.
pub const BN254_IDENTITY_CONTROL_ID: Digest =
    digest!("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404");

/// Verifies a RISC0-based Groth16 proof, using a 32-byte verification key.
///
/// This function checks whether the given [`ProofReceipt`] satisfies the constraints represented by
/// the provided `verification_key`. If successful, it returns an empty `Ok(())`; otherwise,
/// it returns a suitable [`ZkVmError`].
pub fn verify_groth16(receipt: &ProofReceipt, verification_key: &[u8; 32]) -> ZkVmResult<()> {
    let vk = verifying_key();
    let seal = Seal::from_vec(receipt.proof().as_bytes()).unwrap();

    let (a0, a1) = split_digest(ALLOWED_CONTROL_ROOT).map_err(|e| {
        ZkVmError::InvalidProofReceipt(ZkVmProofError::DataFormat(DataFormatError::Other(format!(
            "Invalid Control Root: {}",
            e
        ))))
    })?;

    let public_params_hash = *Sha256Impl::hash_bytes(receipt.public_values().as_bytes());
    let image_id = Digest::from_bytes(*verification_key);

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

/// Computes the digest of Claim without constructing the state
/// TODO: add more detail here
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

#[cfg(test)]
mod tests {
    use risc0_circuit_recursion::control_id::{
        ALLOWED_CONTROL_ROOT as RECURSION_CONTROL_ROOT,
        BN254_IDENTITY_CONTROL_ID as RECURSION_BN256_CONTROL_ID,
    };
    use risc0_zkvm::{Groth16Receipt, MaybePruned, ReceiptClaim};
    use zkaleido::ProofReceipt;

    use super::*;

    fn get_proof_and_digest_id() -> (ProofReceipt, [u8; 32]) {
        let vk_hex = "0963493f27db6efac281ea2900ff4c611a93703cb9109dbd2231484121d08384";
        let vk: [u8; 32] = hex::decode(vk_hex).unwrap().try_into().unwrap();
        let proof_file = format!("./proofs/fibonacci_risc0_{}.proof.bin", vk_hex);

        let receipt = ProofReceipt::load(proof_file).unwrap();

        (receipt, vk)
    }

    fn zkvm_verify_groth16(receipt: &ProofReceipt, verification_key: &[u8; 32]) -> ZkVmResult<()> {
        let public_params_digest = *Sha256Impl::hash_bytes(receipt.public_values().as_bytes());

        let claim = ReceiptClaim::ok(
            risc0_zkvm::sha::Digest::from_bytes(*verification_key),
            MaybePruned::from(receipt.public_values().as_bytes().to_vec()),
        );

        let claim = MaybePruned::from(claim);

        let receipt = Groth16Receipt::new(
            receipt.proof().as_bytes().into(), // Actual Groth16 Proof(A, B, C)
            claim,                             // Includes both digest and elf
            public_params_digest,              /* This is only used underneath to see if it's
                                                * missing */
        );

        // Map the verification error to ZkVmResult and return the result
        receipt
            .verify_integrity()
            .map_err(|e| zkaleido::ZkVmError::ProofVerificationError(e.to_string()))
    }

    #[test]
    fn test_groth16_verification() {
        let (receipt, vk) = get_proof_and_digest_id();
        let res = zkvm_verify_groth16(&receipt, &vk);
        assert!(res.is_ok(), "groth16 proof verification must succeed");

        let res = verify_groth16(&receipt, &vk);
        assert!(res.is_ok(), "groth16 proof verification must succeed");
    }

    #[test]
    fn test_control_values() {
        assert_eq!(ALLOWED_CONTROL_ROOT, RECURSION_CONTROL_ROOT);
        assert_eq!(BN254_IDENTITY_CONTROL_ID, RECURSION_BN256_CONTROL_ID);
    }
}
