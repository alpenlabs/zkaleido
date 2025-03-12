//! # zkaleido-risc0-groth16-verifier
//!
//! This crate integrates RISC Zero-based Groth16 proof verification based on zkaleido traits.
pub mod alt_v;

use risc0_zkvm::{Groth16Receipt, MaybePruned, ReceiptClaim};
use sha2::Digest;
use zkaleido::{ProofReceipt, ZkVmResult};

/// Verifies a RISC0-based Groth16 proof, using a 32-byte verification key.
///
/// This function checks whether the given [`ProofReceipt`] satisfies the constraints represented by
/// the provided `verification_key`. If successful, it returns an empty `Ok(())`; otherwise,
/// it returns a suitable [`ZkVmError`].
pub fn verify_groth16(receipt: &ProofReceipt, verification_key: &[u8; 32]) -> ZkVmResult<()> {
    let public_params_hash: [u8; 32] =
        sha2::Sha256::digest(receipt.public_values().as_bytes()).into();
    let public_params_digest = risc0_zkvm::sha::Digest::from_bytes(public_params_hash);

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
