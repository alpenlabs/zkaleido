use bn::{AffineG1, Fr, G1};
use sha2::{Digest, Sha256};
use zkaleido::{ProofReceipt, ZkVmError, ZkVmResult, ZkVmVerifier};

use crate::{
    error::{BufferLengthError, Groth16Error, SerializationError},
    hashes::{blake3_to_fr, sha256_to_fr},
    types::{
        constant::{SUCCESS_EXIT_CODE, VK_HASH_PREFIX_LENGTH},
        parsed_proof::ParsedSp1Groth16Proof,
        vk::Groth16VerifyingKey,
    },
    verification::verify_sp1_groth16_algebraic,
};

/// A verifier for SP1 Groth16 proofs.
///
/// The verifier holds the values it expects to see committed in the SP1 envelope. The
/// `vk_hash_tag` is always computed at load time from the verifying key. `vk_root` is pinned
/// to this crate's `sp1-verifier` constant. `require_success` controls how the program exit
/// code committed by the proof is enforced — see [`SP1Groth16Verifier::verify`].
#[derive(Clone, Debug)]
pub struct SP1Groth16Verifier {
    /// The (uncompressed) Groth16 verifying key for the SP1 circuit.
    pub vk: Groth16VerifyingKey,
    /// First `VK_HASH_PREFIX_LENGTH` bytes of `Sha256(groth16_vk)`. SP1 prepends this as an
    /// advisory tag on emitted proofs; when the proof carries the tag, it must match.
    pub vk_hash_tag: [u8; VK_HASH_PREFIX_LENGTH],
    /// SP1 recursion verifier-key root committed in the proof envelope.
    pub vk_root: [u8; 32],
    /// When `true`, the verifier requires the proof to commit to a successful exit code
    /// (`SUCCESS_EXIT_CODE`); when `false`, the verifier accepts whatever exit code the proof
    /// commits to but errors if the proof carries no exit code at all.
    pub require_success: bool,
}

impl SP1Groth16Verifier {
    /// Loads a new `SP1Groth16Verifier` from a gnark compressed Groth16 verifying key and a
    /// program ID. This directly bakes fixed SP1 public inputs into the G1-key vector so that
    /// downstream callers only pass statement-specific inputs. `program_vk_hash` and `vk_root`
    /// are fixed by the verifier instance, so the remaining inputs are `hash(public_values)`,
    /// `exit_code`, and `proof_nonce`.
    ///
    /// # Parameters
    /// - `vk_bytes`: Byte slice containing the gnark compressed Groth16 verifying key. Typically,
    ///   this is the [`static@sp1_verifier::GROTH16_VK_BYTES`] constant for the given SP1 version.
    /// - `program_vk_hash`: A 32-byte array representing the Fr-element identifier for the SP1
    ///   program.
    /// - `require_success`: When `true`, the verifier enforces that the proof commits to a
    ///   successful exit code (`SUCCESS_EXIT_CODE`); when `false`, the verifier accepts whatever
    ///   exit code the proof commits to (and errors if the proof carries no exit code).
    pub fn load(
        vk_bytes: &[u8],
        program_vk_hash: [u8; 32],
        require_success: bool,
    ) -> Result<Self, Groth16Error> {
        // Compute the SHA-256 hash of `vk_bytes` and take the first `VK_HASH_PREFIX_LENGTH` bytes.
        // This prefix is prepended to every raw Groth16 proof by SP1 to signal which verifying key
        // was used during proving.
        let digest = Sha256::digest(vk_bytes);
        let mut vk_hash_tag = [0u8; VK_HASH_PREFIX_LENGTH];
        vk_hash_tag.copy_from_slice(&digest[..VK_HASH_PREFIX_LENGTH]);
        let vk_root = *sp1_verifier::VK_ROOT_BYTES;

        // Parse the Groth16 verifying key from its byte representation.
        // This returns a `Groth16VerifyingKey` that can be used for algebraic verification.
        let mut groth16_vk = Groth16VerifyingKey::from_gnark_bytes(vk_bytes)?;

        // Parse the program ID (Fr element) from its 32-byte big-endian encoding.
        let program_vk_hash = Fr::from_slice(&program_vk_hash).map_err(SerializationError::from)?;

        if groth16_vk.g1.k.len() < 2 {
            return Err(Groth16Error::Serialization(
                BufferLengthError {
                    context: "Groth16 VK K points",
                    expected: 2,
                    actual: groth16_vk.g1.k.len(),
                }
                .into(),
            ));
        }

        // Fold the fixed program verification key hash into K0.
        let mut k0: G1 = groth16_vk.g1.k[0].into();
        let k1: G1 = groth16_vk.g1.k[1].into();
        k0 = k0 + (k1 * program_vk_hash);

        // When the verifying key carries `vk_root` as public input 3 (K4), fold it into K0 since
        // the verifier already pins the recursion verifier-key root to this crate's `sp1-verifier`
        // version, and remove original K4 from the dynamic input basis.
        let merge_vk_root = groth16_vk.g1.k.len() >= 6;
        if merge_vk_root {
            let vk_root = Fr::from_slice(&vk_root).map_err(SerializationError::from)?;
            let k4: G1 = groth16_vk.g1.k[4].into();
            k0 = k0 + (k4 * vk_root);
        }

        let mut k = Vec::with_capacity(if merge_vk_root {
            groth16_vk.g1.k.len() - 2
        } else {
            groth16_vk.g1.k.len() - 1
        });
        k.push(AffineG1::from_jacobian(k0).unwrap().into());
        if merge_vk_root {
            k.extend_from_slice(&groth16_vk.g1.k[2..4]);
            k.extend_from_slice(&groth16_vk.g1.k[5..]);
        } else {
            k.extend_from_slice(&groth16_vk.g1.k[2..]);
        }
        groth16_vk.g1.k = k;

        Ok(SP1Groth16Verifier {
            vk: groth16_vk,
            vk_hash_tag,
            vk_root,
            require_success,
        })
    }

    /// Verifies a Groth16 proof against the given public values.
    ///
    /// The proof is expected to be encoded as one of:
    ///
    /// [ vk_hash_prefix (VK_HASH_PREFIX_LENGTH bytes) || raw_groth16_proof_bytes ]
    /// [ vk_hash_prefix || exit_code || vk_root || proof_nonce || raw_groth16_proof_bytes ]
    ///
    /// The envelope metadata (`exit_code`, `vk_root`, `proof_nonce`) is optional: when included,
    /// the verifier checks the bound values against its own; when absent, the verifier falls back
    /// to its configured defaults (`SUCCESS_EXIT_CODE` if `require_success`, zero `proof_nonce`).
    ///
    /// The raw proof bytes can be in either compressed ([`GROTH16_PROOF_COMPRESSED_SIZE`] bytes) or
    /// uncompressed ([`GROTH16_PROOF_UNCOMPRESSED_SIZE`] bytes) format. The verifier automatically
    /// detects both the SP1 proof envelope and the raw proof format based on byte length.
    ///
    /// # Parameters
    /// - `proof`: Byte slice containing the prefixed Groth16 proof.
    /// - `public_values`: Byte slice representing the public values for the SP1 circuit.
    ///
    /// HACK: Because the proof format currently does not encode which hash function (SHA-256 vs.
    /// Blake3) was used to compute the public-values hash, we attempt verification with both:
    /// first using SHA-256, and if that fails, retrying with Blake3. In future versions, this
    /// could be improved by embedding a hash-selector byte in the proof to avoid redundant checks.
    pub fn verify(&self, proof: &[u8], public_values: &[u8]) -> Result<(), Groth16Error> {
        // Parse the SP1 proof envelope (optional vk hash prefix + optional metadata + raw proof).
        let parsed = ParsedSp1Groth16Proof::parse(proof)?;

        // The vk hash tag is an advisory prefix; algebraic verification still binds the proof to
        // `self.vk`. We only enforce equality when the proof actually includes the tag — pruned
        // envelopes that strip it fall through to algebraic verification.
        if let Some(tag) = parsed.vk_hash_tag
            && tag != self.vk_hash_tag
        {
            return Err(Groth16Error::VkeyHashMismatch);
        }

        // vk_root is also only enforced when the proof carries it.
        if let Some(vk_root) = parsed.vk_root
            && vk_root != self.vk_root
        {
            return Err(Groth16Error::VkeyRootMismatch);
        }

        // Decide which exit code to bind into the algebraic public inputs based on
        // `require_success` x whether the proof carried an exit code.
        let expected_exit_code = match (self.require_success, parsed.exit_code) {
            (true, Some(ec)) => {
                if ec != SUCCESS_EXIT_CODE {
                    return Err(Groth16Error::ExitCodeMismatch);
                }
                SUCCESS_EXIT_CODE
            }
            (true, None) => SUCCESS_EXIT_CODE,
            (false, Some(ec)) => ec,
            (false, None) => return Err(Groth16Error::MissingV6Metadata),
        };

        let proof_nonce = parsed.proof_nonce.unwrap_or([0u8; 32]);

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
        if verify_sp1_groth16_algebraic(&self.vk, &parsed.proof, &public_inputs).is_ok() {
            return Ok(());
        }

        // If SHA-256 verification fails, retry with the Blake3 hash of `public_values`.
        public_inputs[0] = blake3_to_fr(public_values)?;
        verify_sp1_groth16_algebraic(&self.vk, &parsed.proof, &public_inputs)
    }
}

impl ZkVmVerifier for SP1Groth16Verifier {
    fn verify(&self, receipt: &ProofReceipt) -> ZkVmResult<()> {
        self.verify(
            receipt.proof().as_bytes(),
            receipt.public_values().as_bytes(),
        )
        .map_err(|e| ZkVmError::ProofVerificationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use bn::{AffineG1, AffineG2, Fq, Fq2, G1, G2, Group};
    use rand::thread_rng;
    use sp1_verifier::GROTH16_VK_BYTES;
    use zkaleido::{ProofReceipt, ProofReceiptWithMetadata};

    use crate::{
        Groth16VerifyingKey, SP1_GROTH16_VK_COMPRESSED_SIZE_MERGED,
        SP1_GROTH16_VK_UNCOMPRESSED_SIZE_MERGED,
        error::Groth16Error,
        types::{
            constant::{
                GROTH16_PROOF_COMPRESSED_SIZE, GROTH16_PROOF_UNCOMPRESSED_SIZE,
                VK_HASH_PREFIX_LENGTH,
            },
            proof::Groth16Proof,
        },
        verifier::SP1Groth16Verifier,
    };

    const SP1_V5_GROTH16_VK_BYTES: &[u8] =
        include_bytes!("../../../../examples/groth16-verify-sp1/vk/sp1_groth16_vk.bin");

    fn load_verifier_and_proof() -> (SP1Groth16Verifier, ProofReceipt) {
        let receipt =
            ProofReceiptWithMetadata::load("./proofs/fibonacci_SP1_v5.0.0.proof.bin").unwrap();

        let verifier = SP1Groth16Verifier::load(
            SP1_V5_GROTH16_VK_BYTES,
            receipt.metadata().program_id().0,
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
    fn test_compressed_and_uncompressed_proof() {
        let (verifier, receipt) = load_verifier_and_proof();
        let proof_bytes = receipt.proof().as_bytes();
        let public_values = receipt.public_values().as_bytes();

        // Extract raw proof (without VK hash prefix)
        let raw_proof_bytes = &proof_bytes[VK_HASH_PREFIX_LENGTH..];

        // Parse the proof
        let parsed_proof = Groth16Proof::from_uncompressed_bytes(raw_proof_bytes).unwrap();

        // Convert to compressed format
        let compressed = parsed_proof.to_gnark_compressed_bytes();
        assert_eq!(compressed.len(), GROTH16_PROOF_COMPRESSED_SIZE);

        // Convert to uncompressed format
        let uncompressed = parsed_proof.to_uncompressed_bytes();
        assert_eq!(uncompressed.len(), GROTH16_PROOF_UNCOMPRESSED_SIZE);

        let vk_hash_tag = verifier.vk_hash_tag;

        // Create proof with VK hash prefix for compressed
        let mut compressed_proof_with_prefix = Vec::new();
        compressed_proof_with_prefix.extend_from_slice(&vk_hash_tag);
        compressed_proof_with_prefix.extend_from_slice(&compressed);

        // Create proof with VK hash prefix for uncompressed
        let mut uncompressed_proof_with_prefix = Vec::new();
        uncompressed_proof_with_prefix.extend_from_slice(&vk_hash_tag);
        uncompressed_proof_with_prefix.extend_from_slice(&uncompressed);

        // Verify both compressed and uncompressed proofs work
        let res_compressed = verifier.verify(&compressed_proof_with_prefix, public_values);
        assert!(
            res_compressed.is_ok(),
            "Compressed proof verification failed: {:?}",
            res_compressed
        );

        let res_uncompressed = verifier.verify(&uncompressed_proof_with_prefix, public_values);
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

    #[test]
    fn test_sp1_v6_vk_load_merges_public_inputs() {
        let verifier = SP1Groth16Verifier::load(&GROTH16_VK_BYTES, [0u8; 32], true).unwrap();

        let gnark_vk_bytes = verifier.vk.to_gnark_bytes();
        assert_eq!(gnark_vk_bytes.len(), SP1_GROTH16_VK_COMPRESSED_SIZE_MERGED);
        let vk = Groth16VerifyingKey::from_gnark_bytes(&gnark_vk_bytes).unwrap();
        assert_eq!(vk, verifier.vk);

        let uncompressed_vk_bytes = verifier.vk.to_uncompressed_bytes();
        assert_eq!(
            uncompressed_vk_bytes.len(),
            SP1_GROTH16_VK_UNCOMPRESSED_SIZE_MERGED
        );
        let vk = Groth16VerifyingKey::from_uncompressed_bytes(&uncompressed_vk_bytes).unwrap();
        assert_eq!(vk, verifier.vk);
    }

    #[test]
    fn test_sp1_v6_proof_rejects_wrong_vk_root() {
        // Reuse a real (uncompressed) Groth16 proof so that point parsing succeeds and the
        // wrong-vk_root error path is actually exercised.
        let (_, receipt) = load_verifier_and_proof();
        let raw_proof_bytes = &receipt.proof().as_bytes()[VK_HASH_PREFIX_LENGTH..];

        let verifier = SP1Groth16Verifier::load(&GROTH16_VK_BYTES, [0u8; 32], true).unwrap();
        let mut proof = Vec::new();
        proof.extend_from_slice(&verifier.vk_hash_tag);
        proof.extend_from_slice(&[0u8; 32]);
        proof.extend_from_slice(&[1u8; 32]);
        proof.extend_from_slice(&[0u8; 32]);
        proof.extend_from_slice(raw_proof_bytes);

        let err = verifier.verify(&proof, &[]).unwrap_err();
        assert!(matches!(err, Groth16Error::VkeyRootMismatch));
    }
}
