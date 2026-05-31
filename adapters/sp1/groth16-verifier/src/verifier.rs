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
    error::{
        BufferLengthError, InvalidDataFormatError, InvalidProofFormatError, SerializationError,
        Sp1Groth16Error,
    },
    hashes::{blake3_to_fr, sha256_to_fr},
    types::{
        constant::{
            G1_COMPRESSED_SIZE, G1_UNCOMPRESSED_SIZE, G2_UNCOMPRESSED_SIZE,
            GNARK_VK_COMPRESSED_HEADER_SIZE, GNARK_VK_COMPRESSED_NUM_K_OFFSET,
            GROTH16_VK_UNCOMPRESSED_HEADER_SIZE, SUCCESS_EXIT_CODE, VK_HASH_PREFIX_LENGTH,
        },
        vk::Groth16VerifyingKey,
    },
    verification::verify_sp1_groth16_algebraic,
};

/// A stateful verifier for SP1 Groth16 proofs.
///
/// Construction (see [`SP1Groth16Verifier::load`]) pre-loads the Groth16 verifying key and
/// bakes the fixed `program_vk_hash` public input into the K basis, so callers of
/// [`SP1Groth16Verifier::verify`] only supply statement-specific inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SP1Groth16Verifier {
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
    /// The (uncompressed) Groth16 verifying key for the SP1 circuit. Crate-private because
    /// [`Groth16VerifyingKey`] is not part of this crate's public surface; downstream callers
    /// interact with the verifier through [`Self::load`], [`Self::verify`], and the canonical
    /// byte (de)serialization methods.
    pub(crate) vk: Groth16VerifyingKey,
}

/// Size of the fixed-width header prepended before the Groth16 verifying key in the canonical
/// [`SP1Groth16Verifier`] encodings: `vk_hash_tag` (4 bytes), `vk_root` (32 bytes), and
/// `require_success` (1 byte).
const VERIFIER_HEADER_SIZE: usize = VK_HASH_PREFIX_LENGTH + 32 + 1;

/// Offset of the `num_k` field within the uncompressed VK header (relative to the start of the
/// verifying key, not the start of the canonical encoding).
const GROTH16_VK_UNCOMPRESSED_NUM_K_OFFSET: usize = G1_UNCOMPRESSED_SIZE + 3 * G2_UNCOMPRESSED_SIZE;

/// Computes the total length a compressed [`SP1Groth16Verifier`] encoding would have if
/// `bytes` were a valid compressed encoding. Returns `None` if `bytes` is too short to even
/// hold the fixed header plus the compressed VK header.
///
/// Used by [`SP1Groth16Verifier::parse`] to dispatch between formats without invoking the
/// (expensive) point-decoding parsers speculatively.
fn compressed_candidate_len(bytes: &[u8]) -> Option<usize> {
    let nk_off = VERIFIER_HEADER_SIZE + GNARK_VK_COMPRESSED_NUM_K_OFFSET;
    let nk_slot: [u8; 4] = bytes.get(nk_off..nk_off + 4)?.try_into().ok()?;
    let num_k = u32::from_be_bytes(nk_slot) as usize;
    let vk_len =
        GNARK_VK_COMPRESSED_HEADER_SIZE.checked_add(num_k.checked_mul(G1_COMPRESSED_SIZE)?)?;
    VERIFIER_HEADER_SIZE.checked_add(vk_len)
}

/// Same as [`compressed_candidate_len`] but for the uncompressed encoding.
fn uncompressed_candidate_len(bytes: &[u8]) -> Option<usize> {
    let nk_off = VERIFIER_HEADER_SIZE + GROTH16_VK_UNCOMPRESSED_NUM_K_OFFSET;
    let nk_slot: [u8; 4] = bytes.get(nk_off..nk_off + 4)?.try_into().ok()?;
    let num_k = u32::from_be_bytes(nk_slot) as usize;
    let vk_len = GROTH16_VK_UNCOMPRESSED_HEADER_SIZE
        .checked_add(num_k.checked_mul(G1_UNCOMPRESSED_SIZE)?)?;
    VERIFIER_HEADER_SIZE.checked_add(vk_len)
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
    /// 3. **Algebraic verification** via the bare Groth16 pairing check.
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

    /// Serialize the verifier to its canonical, self-describing byte representation.
    ///
    /// Layout:
    /// - bytes `0..4`:    `vk_hash_tag`
    /// - bytes `4..36`:   `vk_root`
    /// - byte  `36`:      `require_success` (`0x00` for `false`, `0x01` for `true`)
    /// - bytes `37..`:    uncompressed Groth16 verifying key (length determined by the `num_k`
    ///   field embedded in the VK header)
    ///
    /// The fixed-size header precedes the verifying key, whose embedded `num_k` makes its
    /// length unambiguous, so the encoding needs no outer length prefix. The round-trip pair
    /// is [`Self::from_uncompressed_bytes`].
    pub fn to_uncompressed_bytes(&self) -> Vec<u8> {
        let vk_bytes = self.vk.to_uncompressed_bytes();
        let mut bytes = Vec::with_capacity(VERIFIER_HEADER_SIZE + vk_bytes.len());
        bytes.extend_from_slice(&self.vk_hash_tag);
        bytes.extend_from_slice(&self.vk_root);
        bytes.push(u8::from(self.require_success));
        bytes.extend_from_slice(&vk_bytes);
        bytes
    }

    /// Deserialize a verifier from the canonical encoding produced by
    /// [`Self::to_uncompressed_bytes`].
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, Sp1Groth16Error> {
        let (header, vk_bytes) = Self::split_header(bytes)?;
        // The uncompressed VK parser validates its length exactly, so it rejects a buffer with
        // missing or extra K-point bytes on its own — no length arithmetic needed here.
        let vk = Groth16VerifyingKey::from_uncompressed_bytes(vk_bytes)?;
        Self::assemble_with_header(vk, header)
    }

    /// Serialize the verifier to a self-contained byte representation that uses GNARK's
    /// compressed VK encoding.
    ///
    /// Same layout as [`Self::to_uncompressed_bytes`], but the verifying-key segment uses
    /// GNARK's compressed VK encoding (with `num_k` embedded in its header) so its length is
    /// still unambiguous without an outer length prefix. The round-trip pair is
    /// [`Self::from_compressed_bytes`].
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        let vk_bytes = self.vk.to_gnark_bytes();
        let mut bytes = Vec::with_capacity(VERIFIER_HEADER_SIZE + vk_bytes.len());
        bytes.extend_from_slice(&self.vk_hash_tag);
        bytes.extend_from_slice(&self.vk_root);
        bytes.push(u8::from(self.require_success));
        bytes.extend_from_slice(&vk_bytes);
        bytes
    }

    /// Deserialize a verifier from the compressed encoding produced by
    /// [`Self::to_compressed_bytes`].
    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, Sp1Groth16Error> {
        let (header, vk_bytes) = Self::split_header(bytes)?;
        let vk = Groth16VerifyingKey::from_gnark_bytes(vk_bytes)?;

        // `from_gnark_bytes` tolerates a buffer longer than the VK; the canonical encoding has
        // nothing after the VK, so reject trailing bytes to keep the representation unique.
        let vk_len = GNARK_VK_COMPRESSED_HEADER_SIZE + vk.g1.k.len() * G1_COMPRESSED_SIZE;
        if vk_bytes.len() != vk_len {
            return Err(Sp1Groth16Error::Serialization(
                BufferLengthError {
                    context: "SP1 Groth16 verifier (compressed)",
                    expected: vk_len,
                    actual: vk_bytes.len(),
                }
                .into(),
            ));
        }

        Self::assemble_with_header(vk, header)
    }

    /// Parse a verifier from either the compressed ([`Self::to_compressed_bytes`]) or the
    /// uncompressed ([`Self::to_uncompressed_bytes`]) canonical encoding.
    ///
    /// Detection is structural: both encodings store `num_k` at a known offset within the VK
    /// header, so this function peeks at each candidate offset, computes the implied total
    /// length, and dispatches to the parser whose computed length matches the input buffer.
    /// If neither matches, an `InvalidProofFormatError` is returned without invoking either
    /// parser; if exactly one matches, that parser's error (if any) is the one surfaced — so
    /// callers don't see a misleading "wrong format" error from the fallback.
    ///
    /// In the rare case both candidate lengths happen to coincide (possible when the bytes
    /// at one format's `num_k` offset accidentally satisfy the other format's length
    /// equation), the uncompressed parser is tried first; if it fails, the compressed parser
    /// is tried as a fallback so a buffer that is a valid encoding in *either* form always
    /// parses.
    pub fn parse(bytes: &[u8]) -> Result<Self, Sp1Groth16Error> {
        let compressed_matches = compressed_candidate_len(bytes) == Some(bytes.len());
        let uncompressed_matches = uncompressed_candidate_len(bytes) == Some(bytes.len());

        match (compressed_matches, uncompressed_matches) {
            (true, false) => Self::from_compressed_bytes(bytes),
            (false, true) => Self::from_uncompressed_bytes(bytes),
            (true, true) => {
                Self::from_uncompressed_bytes(bytes).or_else(|_| Self::from_compressed_bytes(bytes))
            }
            (false, false) => Err(Sp1Groth16Error::Serialization(
                InvalidProofFormatError {
                    actual: bytes.len(),
                }
                .into(),
            )),
        }
    }

    /// Split a canonical verifier encoding into its fixed-size header and the trailing
    /// verifying-key bytes.
    ///
    /// Returns a `BufferLengthError` if `bytes` is shorter than [`VERIFIER_HEADER_SIZE`].
    /// Returning the header as a fixed-size array lets [`Self::assemble_with_header`] index
    /// it without a length check, so that routine cannot panic from a future caller bug.
    fn split_header(bytes: &[u8]) -> Result<(&[u8; VERIFIER_HEADER_SIZE], &[u8]), Sp1Groth16Error> {
        let header = bytes.first_chunk::<VERIFIER_HEADER_SIZE>().ok_or_else(|| {
            Sp1Groth16Error::Serialization(
                BufferLengthError {
                    context: "SP1 Groth16 verifier header",
                    expected: VERIFIER_HEADER_SIZE,
                    actual: bytes.len(),
                }
                .into(),
            )
        })?;
        Ok((header, &bytes[VERIFIER_HEADER_SIZE..]))
    }

    /// Assemble a verifier from a parsed verifying key and the fixed-size header that preceded
    /// it in the canonical encodings.
    ///
    /// Rejects a VK with zero K points: the algebraic verifier indexes `vk.g1.k[0]`
    /// unconditionally, so an empty K basis would turn a malformed serialized verifier
    /// into a runtime panic at `verify` time. `load` produces a folded VK whose K length
    /// equals `raw_num_k - 1` and enforces `raw_num_k >= 2`, so any verifier obtained
    /// through the supported constructors has at least one K point; we re-check it here
    /// because the deserialization path accepts an arbitrary `num_k` from the encoding.
    fn assemble_with_header(
        vk: Groth16VerifyingKey,
        header: &[u8; VERIFIER_HEADER_SIZE],
    ) -> Result<Self, Sp1Groth16Error> {
        if vk.g1.k.is_empty() {
            return Err(Sp1Groth16Error::Serialization(
                BufferLengthError {
                    context: "SP1 Groth16 verifier K points",
                    expected: 1,
                    actual: 0,
                }
                .into(),
            ));
        }

        let mut vk_hash_tag = [0u8; VK_HASH_PREFIX_LENGTH];
        vk_hash_tag.copy_from_slice(&header[..VK_HASH_PREFIX_LENGTH]);

        let mut vk_root = [0u8; 32];
        vk_root.copy_from_slice(&header[VK_HASH_PREFIX_LENGTH..VK_HASH_PREFIX_LENGTH + 32]);

        let require_success = match header[VK_HASH_PREFIX_LENGTH + 32] {
            0 => false,
            1 => true,
            _ => {
                return Err(Sp1Groth16Error::Serialization(
                    InvalidDataFormatError.into(),
                ));
            }
        };

        Ok(SP1Groth16Verifier {
            vk,
            vk_hash_tag,
            vk_root,
            require_success,
        })
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

    use super::{GROTH16_VK_UNCOMPRESSED_NUM_K_OFFSET, VERIFIER_HEADER_SIZE};
    use crate::{
        Sp1Groth16Proof,
        error::{BufferLengthError, SerializationError, Sp1Groth16Error},
        types::{
            constant::{
                GNARK_VK_COMPRESSED_HEADER_SIZE, GNARK_VK_COMPRESSED_NUM_K_OFFSET,
                GROTH16_PROOF_COMPRESSED_SIZE, GROTH16_PROOF_UNCOMPRESSED_SIZE,
                GROTH16_VK_UNCOMPRESSED_HEADER_SIZE, SUCCESS_EXIT_CODE, VK_HASH_PREFIX_LENGTH,
            },
            vk::Groth16VerifyingKey,
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

    #[test]
    fn test_verifier_uncompressed_roundtrip() {
        let (verifier, receipt) = load_verifier_and_proof();

        let bytes = verifier.to_uncompressed_bytes();
        let recovered = SP1Groth16Verifier::from_uncompressed_bytes(&bytes).unwrap();

        assert_eq!(recovered, verifier);

        // The recovered verifier should still verify the original proof.
        recovered
            .verify(
                receipt.proof().as_bytes(),
                receipt.public_values().as_bytes(),
            )
            .unwrap();
    }

    #[test]
    fn test_verifier_uncompressed_require_success_false_roundtrip() {
        let (mut verifier, _) = load_verifier_and_proof();
        verifier.require_success = false;

        let bytes = verifier.to_uncompressed_bytes();
        let recovered = SP1Groth16Verifier::from_uncompressed_bytes(&bytes).unwrap();
        assert!(!recovered.require_success);
    }

    #[test]
    fn test_verifier_from_uncompressed_bytes_invalid() {
        let (verifier, _) = load_verifier_and_proof();
        let bytes = verifier.to_uncompressed_bytes();

        // Truncated buffer.
        assert!(SP1Groth16Verifier::from_uncompressed_bytes(&bytes[..bytes.len() - 1]).is_err());

        // The `require_success` byte in the header must be 0 or 1.
        let mut tampered = bytes.clone();
        tampered[VK_HASH_PREFIX_LENGTH + 32] = 2;
        assert!(SP1Groth16Verifier::from_uncompressed_bytes(&tampered).is_err());
    }

    #[test]
    fn test_verifier_compressed_roundtrip() {
        let (verifier, receipt) = load_verifier_and_proof();

        let bytes = verifier.to_compressed_bytes();
        // Compressed form should be smaller than the uncompressed form.
        assert!(bytes.len() < verifier.to_uncompressed_bytes().len());

        let recovered = SP1Groth16Verifier::from_compressed_bytes(&bytes).unwrap();
        assert_eq!(recovered, verifier);

        recovered
            .verify(
                receipt.proof().as_bytes(),
                receipt.public_values().as_bytes(),
            )
            .unwrap();
    }

    #[test]
    fn test_verifier_from_compressed_bytes_invalid() {
        let (verifier, _) = load_verifier_and_proof();
        let bytes = verifier.to_compressed_bytes();

        // Truncated buffer.
        assert!(SP1Groth16Verifier::from_compressed_bytes(&bytes[..bytes.len() - 1]).is_err());

        // The `require_success` byte in the header must be 0 or 1.
        let mut tampered = bytes.clone();
        tampered[VK_HASH_PREFIX_LENGTH + 32] = 2;
        assert!(SP1Groth16Verifier::from_compressed_bytes(&tampered).is_err());
    }

    /// A malicious payload with `num_k = 0` parses into a `Groth16VerifyingKey` with an empty
    /// K basis. The algebraic verifier indexes `vk.g1.k[0]` unconditionally, so without an
    /// explicit reject the malformed bytes would silently produce a verifier whose `verify`
    /// call later panics.
    ///
    /// The payload is built from a valid serialized verifier (so the G1/G2 coordinates
    /// decode) with only the `num_k` field overwritten and the K bytes dropped, ensuring
    /// the failure must come from the empty-K check rather than from upstream length or
    /// point validation.
    #[test]
    fn test_verifier_rejects_zero_k_num_k() {
        let (verifier, _) = load_verifier_and_proof();

        // Keep the fixed header plus the VK header, drop all K bytes, and zero `num_k`.
        let uncompressed = verifier.to_uncompressed_bytes();
        let mut tampered =
            uncompressed[..VERIFIER_HEADER_SIZE + GROTH16_VK_UNCOMPRESSED_HEADER_SIZE].to_vec();
        let num_k_offset = VERIFIER_HEADER_SIZE + GROTH16_VK_UNCOMPRESSED_NUM_K_OFFSET;
        tampered[num_k_offset..num_k_offset + 4].copy_from_slice(&0u32.to_be_bytes());
        let err = SP1Groth16Verifier::from_uncompressed_bytes(&tampered).unwrap_err();
        assert!(matches!(
            err,
            Sp1Groth16Error::Serialization(SerializationError::BufferLength(BufferLengthError {
                context: "SP1 Groth16 verifier K points",
                expected: 1,
                actual: 0,
            }))
        ));

        let compressed = verifier.to_compressed_bytes();
        let mut tampered =
            compressed[..VERIFIER_HEADER_SIZE + GNARK_VK_COMPRESSED_HEADER_SIZE].to_vec();
        let num_k_offset = VERIFIER_HEADER_SIZE + GNARK_VK_COMPRESSED_NUM_K_OFFSET;
        tampered[num_k_offset..num_k_offset + 4].copy_from_slice(&0u32.to_be_bytes());
        let err = SP1Groth16Verifier::from_compressed_bytes(&tampered).unwrap_err();
        assert!(matches!(
            err,
            Sp1Groth16Error::Serialization(SerializationError::BufferLength(BufferLengthError {
                context: "SP1 Groth16 verifier K points",
                expected: 1,
                actual: 0,
            }))
        ));
    }

    #[test]
    fn test_verifier_parse_accepts_both_forms() {
        let (verifier, _) = load_verifier_and_proof();

        let compressed = verifier.to_compressed_bytes();
        let uncompressed = verifier.to_uncompressed_bytes();
        assert_ne!(compressed.len(), uncompressed.len());

        let from_compressed = SP1Groth16Verifier::parse(&compressed).unwrap();
        let from_uncompressed = SP1Groth16Verifier::parse(&uncompressed).unwrap();

        assert_eq!(from_compressed, verifier);
        assert_eq!(from_uncompressed, verifier);
    }

    #[test]
    fn test_verifier_parse_rejects_garbage() {
        // A buffer matching neither encoding's length should fail to parse with
        // `InvalidProofFormat`. 17 bytes is below every plausible header size, so neither
        // candidate length computation succeeds.
        let garbage = vec![0xAAu8; 17];
        let err = SP1Groth16Verifier::parse(&garbage).unwrap_err();
        assert!(matches!(
            err,
            Sp1Groth16Error::Serialization(SerializationError::InvalidProofFormat(_))
        ));
    }

    #[test]
    fn test_verifier_parse_surfaces_format_specific_error() {
        // When the buffer length matches the uncompressed format but the VK bytes are
        // corrupted, `parse` should return the uncompressed parser's error — not silently
        // fall back to compressed (which would give a misleading error from a different
        // format).
        let (verifier, _) = load_verifier_and_proof();
        let mut bytes = verifier.to_uncompressed_bytes();
        // Corrupt a coordinate inside G1 alpha (the first VK field, just past the header) so
        // the uncompressed parser fails at the point-decoding stage.
        bytes[VERIFIER_HEADER_SIZE] ^= 0xFF;
        bytes[VERIFIER_HEADER_SIZE + 1] ^= 0xFF;

        let err = SP1Groth16Verifier::parse(&bytes).unwrap_err();
        // The error must come from the uncompressed parser's point validation — not from
        // length mismatch (which would indicate the parser was never invoked).
        assert!(!matches!(
            err,
            Sp1Groth16Error::Serialization(SerializationError::InvalidProofFormat(_))
        ));
    }
}

// See the crate-level "Backwards compatibility with SP1 v5" docs for why this verifies
// under the v6-shaped public-input vector.
#[cfg(test)]
mod v5_tests {
    use zkaleido::{ProofReceipt, ProofReceiptWithMetadata};

    use crate::{SP1Groth16Verifier, types::constant::VK_HASH_PREFIX_LENGTH};

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
