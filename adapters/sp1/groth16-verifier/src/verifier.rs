//! Hosts [`SP1Groth16Verifier`], the crate's stateful SP1 Groth16 proof verifier.
//!
//! See the [crate-level docs](crate) for the operational model, the module map, the K0
//! pre-folding optimisation, and the trust boundaries enforced by `verify`. This module
//! just wires those pieces together: [`Sp1Groth16Proof`] for prefix-field parsing,
//! [`verify_sp1_groth16_algebraic`](crate::verify_sp1_groth16_algebraic) for the pairing
//! check, and [`crate::hashes`] for the `public_values` hash. The [`ZkVmVerifier`] impl
//! at the bottom of the file is a thin adapter that stringifies `Groth16Error` into
//! `ZkVmError` so the verifier can be used through the trait.

use bn::{AffineG1, Fr, G1};
use sha2::{Digest, Sha256};
use zkaleido::{ProofReceipt, ZkVmError, ZkVmResult, ZkVmVerifier};

use crate::{
    Sp1Groth16Proof,
    error::{BufferLengthError, SerializationError, Sp1Groth16Error},
    hashes::{blake3_to_fr, sha256_to_fr},
    types::{
        constant::{SUCCESS_EXIT_CODE, VK_HASH_PREFIX_LENGTH},
        vk::Groth16VerifyingKey,
    },
    verification::verify_sp1_groth16_algebraic,
};

/// A stateful verifier for SP1 Groth16 proofs.
///
/// Construction (see [`SP1Groth16Verifier::load`]) pre-loads the Groth16 verifying key and
/// bakes the fixed `program_vk_hash` public input into the K basis, so callers of
/// [`SP1Groth16Verifier::verify`] only supply statement-specific inputs.
#[derive(Clone, Debug)]
pub struct SP1Groth16Verifier {
    /// The (uncompressed) Groth16 verifying key for the SP1 circuit.
    pub vk: Groth16VerifyingKey,
    /// First `VK_HASH_PREFIX_LENGTH` bytes of `Sha256(groth16_vk)`. SP1 prepends this as an
    /// advisory tag on emitted proofs; when the proof carries the tag, it must match.
    pub vk_hash_tag: [u8; VK_HASH_PREFIX_LENGTH],
    /// SP1 recursion verifier-key root pinned by this verifier. Bound to the proof as a public
    /// input during algebraic verification, and cross-checked against the proof's `vk_root`
    /// prefix field when the proof carries it.
    pub vk_root: [u8; 32],
    /// When `true`, the verifier requires the proof to commit to a successful exit code
    /// (`SUCCESS_EXIT_CODE`); when `false`, the verifier accepts whatever exit code the proof
    /// commits to but errors if the proof carries no exit code at all.
    pub require_success: bool,
}

impl SP1Groth16Verifier {
    /// Build a `SP1Groth16Verifier` from a GNARK-compressed Groth16 verifying key and a program
    /// identifier.
    ///
    /// `load` does two things beyond plain VK parsing:
    ///
    /// 1. Computes `vk_hash_tag = Sha256(vk_bytes)[..VK_HASH_PREFIX_LENGTH]`, the advisory prefix
    ///    SP1 prepends to emitted proofs.
    /// 2. **Folds `program_vk_hash` into K0.** SP1's circuit takes `(program_vk_hash,
    ///    hash(public_values), exit_code, vk_root, proof_nonce)` as public inputs. Since
    ///    `program_vk_hash` is constant for a given verifier instance, we pre-compute `K0 +
    ///    program_vk_hash·K1` once at load time and remove `K1` from the dynamic input basis.
    ///    Verification then only needs to scalar-multiply against the remaining statement-specific
    ///    inputs.
    pub fn load(
        vk_bytes: &[u8],
        program_vk_hash: [u8; 32],
        vk_root: [u8; 32],
        require_success: bool,
    ) -> Result<Self, Sp1Groth16Error> {
        // Compute the SHA-256 hash of `vk_bytes` and take the first `VK_HASH_PREFIX_LENGTH` bytes.
        // This prefix is prepended to every raw Groth16 proof by SP1 to signal which verifying key
        // was used during proving.
        let digest = Sha256::digest(vk_bytes);
        let mut vk_hash_tag = [0u8; VK_HASH_PREFIX_LENGTH];
        vk_hash_tag.copy_from_slice(&digest[..VK_HASH_PREFIX_LENGTH]);

        // Parse the Groth16 verifying key from its byte representation.
        // This returns a `Groth16VerifyingKey` that can be used for algebraic verification.
        let mut groth16_vk = Groth16VerifyingKey::from_gnark_bytes(vk_bytes)?;

        // Parse the program ID (Fr element) from its 32-byte big-endian encoding.
        let program_vk_hash = Fr::from_slice(&program_vk_hash).map_err(SerializationError::from)?;

        if groth16_vk.g1.k.len() < 2 {
            return Err(Sp1Groth16Error::Serialization(
                BufferLengthError {
                    context: "Groth16 VK K points",
                    expected: 2,
                    actual: groth16_vk.g1.k.len(),
                }
                .into(),
            ));
        }

        // Fold the fixed program verification key hash into K0 and remove K1 from the dynamic
        // input basis.
        let mut k0: G1 = groth16_vk.g1.k[0].into();
        let k1: G1 = groth16_vk.g1.k[1].into();
        k0 = k0 + (k1 * program_vk_hash);

        let mut k = Vec::with_capacity(groth16_vk.g1.k.len() - 1);
        k.push(AffineG1::from_jacobian(k0).unwrap().into());
        k.extend_from_slice(&groth16_vk.g1.k[2..]);
        groth16_vk.g1.k = k;

        Ok(SP1Groth16Verifier {
            vk: groth16_vk,
            vk_hash_tag,
            vk_root,
            require_success,
        })
    }

    /// Verify an already-parsed SP1 Groth16 proof against the given public values.
    ///
    /// This is the canonical verification routine. The bytes-form
    /// [`Self::verify`] just parses its input and delegates here.
    ///
    /// 1. **Cross-checks.** If the proof carries `vk_hash_tag` or `vk_root`, each must equal the
    ///    verifier's pinned value, otherwise it is silently accepted (the algebraic check below
    ///    still binds the proof to `self.vk`). If the proof carries `exit_code`, it is checked
    ///    against `SUCCESS_EXIT_CODE` when `require_success` is set.
    /// 2. **Resolve missing fields.** A missing `exit_code` is filled from `require_success`:
    ///    `SUCCESS_EXIT_CODE` when set, a `Groth16Error::MissingExitCode` when not. A missing
    ///    `proof_nonce` defaults to zero. `vk_root` is sourced from `self.vk_root` regardless of
    ///    whether the proof carried it.
    /// 3. **Algebraic verification** via [`verify_sp1_groth16_algebraic`].
    ///
    /// # HACK: SHA-256 / Blake3 retry
    /// SP1's Groth16 circuit accepts either SHA-256 or Blake3 for `hash(public_values)`, and
    /// the on-wire format does not record which was used. We try SHA-256 first, then retry
    /// with Blake3 if that fails. A future format revision could embed a hash-selector byte to
    /// avoid the redundant pairing check.
    pub fn verify_parsed(
        &self,
        proof: &Sp1Groth16Proof,
        public_values: &[u8],
    ) -> Result<(), Sp1Groth16Error> {
        // The vk hash tag is an advisory prefix; algebraic verification still binds the proof to
        // `self.vk`. We only enforce equality when the proof actually includes the tag — proofs
        // without the tag prefix fall through to algebraic verification.
        if let Some(tag) = proof.vk_hash_tag
            && tag != self.vk_hash_tag
        {
            return Err(Sp1Groth16Error::VkeyHashMismatch {
                expected: self.vk_hash_tag,
                actual: tag,
            });
        }

        // vk_root is also only enforced when the proof carries it.
        if let Some(vk_root) = proof.vk_root
            && vk_root != self.vk_root
        {
            return Err(Sp1Groth16Error::VkeyRootMismatch {
                expected: self.vk_root,
                actual: vk_root,
            });
        }

        // Decide which exit code to bind into the algebraic public inputs based on
        // `require_success` x whether the proof carried an exit code.
        let expected_exit_code = match (self.require_success, proof.exit_code) {
            (true, Some(ec)) => {
                if ec != SUCCESS_EXIT_CODE {
                    return Err(Sp1Groth16Error::ExitCodeMismatch {
                        expected: SUCCESS_EXIT_CODE,
                        actual: ec,
                    });
                }
                SUCCESS_EXIT_CODE
            }
            (true, None) => SUCCESS_EXIT_CODE,
            (false, Some(ec)) => ec,
            (false, None) => return Err(Sp1Groth16Error::MissingExitCode),
        };

        let proof_nonce = proof.proof_nonce.unwrap_or([0u8; 32]);

        // Compute Fr element for hash(public_values) using SHA-256. SP1's Groth16 circuit expects
        // a program vkey hash, hash(public_values), and SP1-version-specific metadata. Since SP1
        // allows either SHA-256 or Blake3 for the public values hash, we try SHA-256 first.
        let public_values_sha2 = sha256_to_fr(public_values)?;

        let mut public_inputs = [
            public_values_sha2,
            Fr::from_slice(&expected_exit_code).map_err(SerializationError::from)?,
            Fr::from_slice(&self.vk_root).map_err(SerializationError::from)?,
            Fr::from_slice(&proof_nonce).map_err(SerializationError::from)?,
        ];

        // Attempt algebraic verification with SHA-256 hash as the public-values input.
        if verify_sp1_groth16_algebraic(&self.vk, &proof.proof, &public_inputs).is_ok() {
            return Ok(());
        }

        // If SHA-256 verification fails, retry with the Blake3 hash of `public_values`.
        public_inputs[0] = blake3_to_fr(public_values)?;
        verify_sp1_groth16_algebraic(&self.vk, &proof.proof, &public_inputs)
    }

    /// Verify an SP1 Groth16 proof in any of the accepted byte encodings.
    ///
    /// Parses `proof` via [`Sp1Groth16Proof::parse`] (which accepts the bare
    /// compressed/uncompressed Groth16 proof through the full prefix-bearing form) and
    /// delegates to [`Self::verify_parsed`] for the cross-checks, missing-field
    /// resolution, and algebraic verification.
    pub fn verify(&self, proof: &[u8], public_values: &[u8]) -> Result<(), Sp1Groth16Error> {
        let parsed = Sp1Groth16Proof::parse(proof)?;
        self.verify_parsed(&parsed, public_values)
    }
}

/// Adapts [`SP1Groth16Verifier`] to the generic [`ZkVmVerifier`] trait.
///
/// Forwards to the inherent [`SP1Groth16Verifier::verify`] and stringifies any
/// `Groth16Error` into [`ZkVmError::ProofVerificationError`] to fit the trait's error
/// type. Callers that need to discriminate between, say, a VK-tag mismatch and an
/// algebraic verification failure should call the inherent method directly.
impl ZkVmVerifier for SP1Groth16Verifier {
    fn verify(&self, receipt: &ProofReceipt) -> ZkVmResult<()> {
        SP1Groth16Verifier::verify(
            self,
            receipt.proof().as_bytes(),
            receipt.public_values().as_bytes(),
        )
        .map_err(|e| ZkVmError::ProofVerificationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use bn::{AffineG1, AffineG2, Fq, Fq2, G1, G2, Group};
    use rand::{Rng, thread_rng};
    use sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES};
    use zkaleido::{ProofReceipt, ProofReceiptWithMetadata};

    use crate::{
        Groth16VerifyingKey, Sp1Groth16Proof,
        error::Sp1Groth16Error,
        types::constant::{
            GROTH16_PROOF_COMPRESSED_SIZE, GROTH16_PROOF_UNCOMPRESSED_SIZE, SUCCESS_EXIT_CODE,
            VK_HASH_PREFIX_LENGTH,
        },
        verifier::SP1Groth16Verifier,
    };
    fn load_verifier_and_proof() -> (SP1Groth16Verifier, ProofReceipt) {
        let receipt =
            ProofReceiptWithMetadata::load("./proofs/fibonacci_SP1_v6.1.0.proof.bin").unwrap();

        let verifier = SP1Groth16Verifier::load(
            &GROTH16_VK_BYTES,
            receipt.metadata().program_id().0,
            *VK_ROOT_BYTES,
            true,
        )
        .unwrap();

        let receipt = receipt.receipt().clone();

        (verifier, receipt)
    }

    #[test]
    fn test_valid_proof() {
        let (verifier, receipt) = load_verifier_and_proof();
        let res = verifier.verify(
            receipt.proof().as_bytes(),
            receipt.public_values().as_bytes(),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_invalid_vk_root() {
        let (mut verifier, receipt) = load_verifier_and_proof();

        // Flip a single random bit in the verifier's vk_root so it no longer matches the value
        // baked into the proof.
        let mut rng = thread_rng();
        let byte_idx = rng.gen_range(0..verifier.vk_root.len());
        let bit_idx = rng.gen_range(0..8);
        verifier.vk_root[byte_idx] ^= 1u8 << bit_idx;

        // The compressed proof carries the vk_root, so we preemptively check it
        // and fail fast with `VkeyRootMismatch` before running the pairing check.
        let err = verifier
            .verify(
                receipt.proof().as_bytes(),
                receipt.public_values().as_bytes(),
            )
            .unwrap_err();
        assert!(matches!(err, Sp1Groth16Error::VkeyRootMismatch { .. }));

        // The uncompressed proof bytes don't include the vk_root, so the preemptive
        // check is skipped and the mismatch only surfaces later as a pairing failure.
        let parsed_proof = Sp1Groth16Proof::parse(receipt.proof().as_bytes()).unwrap();
        let err = verifier
            .verify(
                &parsed_proof.proof.to_uncompressed_bytes(),
                receipt.public_values().as_bytes(),
            )
            .unwrap_err();
        assert!(matches!(err, Sp1Groth16Error::VerificationFailed));
    }

    #[test]
    fn test_invalid_nonce() {
        let (verifier, receipt) = load_verifier_and_proof();
        let proof_bytes = receipt.proof().as_bytes();

        // Sanity-check the original proof verifies and carries a nonce.
        let original = Sp1Groth16Proof::parse(proof_bytes).unwrap();

        // Wire layout when the full prefix is present:
        //   [vk_hash_tag(V) || exit_code(32) || vk_root(32) || proof_nonce(32) || proof]
        // Flip a bit in the nonce region without touching any other field.
        let nonce_offset = VK_HASH_PREFIX_LENGTH + 32 + 32;
        let mut tampered = proof_bytes.to_vec();
        tampered[nonce_offset] ^= 0x01;

        // The modified bytes should still parse, with every field except the nonce unchanged.
        let modified = Sp1Groth16Proof::parse(&tampered).unwrap();
        assert_eq!(modified.vk_hash_tag, original.vk_hash_tag);
        assert_eq!(modified.exit_code, original.exit_code);
        assert_eq!(modified.vk_root, original.vk_root);
        assert_ne!(modified.proof_nonce, original.proof_nonce);
        assert_eq!(
            modified.proof.to_uncompressed_bytes(),
            original.proof.to_uncompressed_bytes()
        );

        // No preemptive nonce check exists, so the mismatch surfaces at the pairing step.
        let err = verifier
            .verify(&tampered, receipt.public_values().as_bytes())
            .unwrap_err();
        assert!(matches!(err, Sp1Groth16Error::VerificationFailed));
    }

    #[test]
    fn test_invalid_public_values() {
        let (verifier, receipt) = load_verifier_and_proof();
        let proof_bytes = receipt.proof().as_bytes();
        let public_values = receipt.public_values().as_bytes();

        // Sanity-check the unmodified inputs verify.
        assert!(verifier.verify(proof_bytes, public_values).is_ok());

        // Flip a single bit at a random position in the public values. The verifier hashes
        // these bytes (SHA-256, with Blake3 fallback) into the algebraic public-input vector,
        // so any change should make the pairing fail.
        let mut rng = thread_rng();
        let byte_idx = rng.gen_range(0..public_values.len());
        let bit_idx = rng.gen_range(0..8);

        let mut tampered = public_values.to_vec();
        tampered[byte_idx] ^= 1u8 << bit_idx;
        assert_ne!(tampered, public_values);

        let err = verifier.verify(proof_bytes, &tampered).unwrap_err();
        assert!(matches!(err, Sp1Groth16Error::VerificationFailed));
    }

    #[test]
    fn test_invalid_exit_code() {
        let (verifier, receipt) = load_verifier_and_proof();
        let proof_bytes = receipt.proof().as_bytes();
        let public_values = receipt.public_values().as_bytes();

        // Wire layout: [vk_hash_tag(V) || exit_code(32) || vk_root(32) || proof_nonce(32) ||
        // proof].
        let exit_code_offset = VK_HASH_PREFIX_LENGTH;

        let mut tampered_exit_code = [0u8; 32];
        thread_rng().fill(&mut tampered_exit_code);
        assert_ne!(tampered_exit_code, SUCCESS_EXIT_CODE);

        let mut tampered = proof_bytes.to_vec();
        tampered[exit_code_offset..exit_code_offset + 32].copy_from_slice(&tampered_exit_code);

        // With `require_success = true`, the cross-check fires before the pairing, returning
        // an `ExitCodeMismatch` whose `actual` matches the bytes we just spliced in.
        let err = verifier.verify(&tampered, public_values).unwrap_err();
        match err {
            Sp1Groth16Error::ExitCodeMismatch { expected, actual } => {
                assert_eq!(expected, SUCCESS_EXIT_CODE);
                assert_eq!(actual, tampered_exit_code);
            }
            other => panic!("expected ExitCodeMismatch, got {other:?}"),
        }

        // With `require_success = false`, the cross-check is skipped and the tampered exit
        // code is fed straight into the algebraic public inputs, so the pairing rejects it.
        let mut permissive = verifier.clone();
        permissive.require_success = false;
        let err = permissive.verify(&tampered, public_values).unwrap_err();
        assert!(matches!(err, Sp1Groth16Error::VerificationFailed));
    }

    #[test]
    fn test_invalid_g1() {
        let (mut verifier, receipt) = load_verifier_and_proof();
        let vk_alpha = verifier.vk.g1.alpha.0;
        let alpha_x = vk_alpha.x();
        let alpha_y = vk_alpha.y();

        let mut rng = thread_rng();
        let invalid_alpha_x = Fq::random(&mut rng);

        let res = AffineG1::new(alpha_x, alpha_y);
        assert!(res.is_ok());

        let res = AffineG1::new(invalid_alpha_x, alpha_y);
        assert!(res.is_err());

        let invalid_alpha =
            AffineG1::from_jacobian(G1::new(invalid_alpha_x, alpha_y, Fq::one())).unwrap();
        verifier.vk.g1.alpha.0 = invalid_alpha;

        let res = verifier.verify(
            receipt.proof().as_bytes(),
            receipt.public_values().as_bytes(),
        );
        assert!(res.is_err());

        let random_alpha = AffineG1::from_jacobian(G1::random(&mut rng)).unwrap();
        verifier.vk.g1.alpha.0 = random_alpha;
        let res = verifier.verify(
            receipt.proof().as_bytes(),
            receipt.public_values().as_bytes(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_invalid_g2() {
        let (mut verifier, receipt) = load_verifier_and_proof();
        let vk_gamma = verifier.vk.g2.gamma.0;
        let gamma_x = vk_gamma.x();
        let gamma_y = vk_gamma.y();
        let invalid_gamma_x = gamma_x + Fq2::one();

        let res = AffineG2::new(gamma_x, gamma_y);
        assert!(res.is_ok());

        let res = AffineG2::new(invalid_gamma_x, gamma_y);
        assert!(res.is_err());

        let invalid_gamma =
            AffineG2::from_jacobian(G2::new(invalid_gamma_x, gamma_y, Fq2::one())).unwrap();
        verifier.vk.g2.gamma.0 = invalid_gamma;

        let res = verifier.verify(
            receipt.proof().as_bytes(),
            receipt.public_values().as_bytes(),
        );
        assert!(res.is_err());

        let mut rng = thread_rng();
        let random_gamma = AffineG2::from_jacobian(G2::random(&mut rng)).unwrap();
        verifier.vk.g2.gamma.0 = random_gamma;
        let res = verifier.verify(
            receipt.proof().as_bytes(),
            receipt.public_values().as_bytes(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_compressed_and_uncompressed_proof_v6() {
        let (verifier, receipt) = load_verifier_and_proof();
        let proof_bytes = receipt.proof().as_bytes();
        let public_values = receipt.public_values().as_bytes();

        // Parse the proof
        let parsed_proof = Sp1Groth16Proof::parse(proof_bytes).unwrap();

        // Convert to compressed format
        let compressed_proof = parsed_proof.proof.to_gnark_compressed_bytes();
        assert_eq!(compressed_proof.len(), GROTH16_PROOF_COMPRESSED_SIZE);

        // Convert to uncompressed format
        let uncompressed_proof = parsed_proof.proof.to_uncompressed_bytes();
        assert_eq!(uncompressed_proof.len(), GROTH16_PROOF_UNCOMPRESSED_SIZE);

        // Verify both compressed and uncompressed proofs work
        let res_compressed = verifier.verify(&compressed_proof, public_values);
        assert!(
            res_compressed.is_ok(),
            "Compressed proof verification failed: {:?}",
            res_compressed
        );

        let res_uncompressed = verifier.verify(&uncompressed_proof, public_values);
        assert!(
            res_uncompressed.is_ok(),
            "Uncompressed proof verification failed: {:?}",
            res_uncompressed
        );
    }

    #[test]
    fn test_compressed_merged_vk_roundtrip() {
        let (verifier, _) = load_verifier_and_proof();

        let gnark_vk_bytes = verifier.vk.to_gnark_bytes();
        let vk = Groth16VerifyingKey::from_gnark_bytes(&gnark_vk_bytes).unwrap();
        assert_eq!(vk, verifier.vk);

        let uncompressed_vk_bytes = verifier.vk.to_uncompressed_bytes();
        let vk = Groth16VerifyingKey::from_uncompressed_bytes(&uncompressed_vk_bytes).unwrap();
        assert_eq!(vk, verifier.vk);
    }
}

// See the crate-level "Backwards compatibility with SP1 v5" docs for why this verifies
// under the v6-shaped public-input vector.
#[cfg(test)]
mod v5_tests {
    use zkaleido::{ProofReceipt, ProofReceiptWithMetadata};

    use crate::{SP1Groth16Verifier, VK_HASH_PREFIX_LENGTH};

    fn load_v5_verifier_and_proof() -> (SP1Groth16Verifier, ProofReceipt) {
        const SP1_V5_GROTH16_VK_BYTES: &[u8] =
            include_bytes!("../../../../examples/groth16-verify-sp1/vk/sp1_groth16_vk_v5.bin");
        const SP1_V5_VK_ROOT: [u8; 32] = [0u8; 32];

        let receipt =
            ProofReceiptWithMetadata::load("./proofs/fibonacci_SP1_v5.0.0.proof.bin").unwrap();

        let verifier = SP1Groth16Verifier::load(
            SP1_V5_GROTH16_VK_BYTES,
            receipt.metadata().program_id().0,
            SP1_V5_VK_ROOT,
            true,
        )
        .unwrap();

        let receipt = receipt.receipt().clone();

        (verifier, receipt)
    }

    #[test]
    fn test_valid_v5_proof() {
        let (verifier, receipt) = load_v5_verifier_and_proof();
        let res = verifier.verify(
            &receipt.proof().as_bytes()[VK_HASH_PREFIX_LENGTH..],
            receipt.public_values().as_bytes(),
        );
        assert!(res.is_ok());
    }
}
