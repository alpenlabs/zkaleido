use bn::Fr;

use crate::{
    error::{Groth16Error, InvalidProofFormatError, SerializationError},
    types::{
        constant::{
            GROTH16_PROOF_COMPRESSED_SIZE, GROTH16_PROOF_UNCOMPRESSED_SIZE, VK_HASH_PREFIX_LENGTH,
        },
        proof::Groth16Proof,
    },
};

/// Number of 32-byte public-input fields embedded in SP1 6.1.0 Groth16 proofs:
/// exit code, recursion verifying-key root, and proof nonce.
const SP1_V6_PROOF_METADATA_LENGTH: usize = 32 * 3;

/// SP1 Groth16 proof together with any envelope fields recovered from its byte encoding.
///
/// The wire format SP1 emits is:
///
/// ```text
/// [ vk_hash_prefix (VK_HASH_PREFIX_LENGTH bytes) || raw_groth16_proof_bytes ]            (SP1 v5)
/// [ vk_hash_prefix || exit_code || vk_root || proof_nonce || raw_groth16_proof_bytes ]   (SP1 v6+)
/// ```
///
/// Only [`Self::proof`] is required — every other field is optional and is populated only when
/// the corresponding bytes were present in the input. This lets callers feed [`Self::parse`] any
/// pruned form of the wire format (raw proof; vk-hash + proof; metadata + proof; full envelope)
/// and still get a uniform value back.
#[derive(Clone, Debug)]
pub struct ParsedSp1Groth16Proof {
    /// The underlying Groth16 proof.
    pub proof: Groth16Proof,
    /// First `VK_HASH_PREFIX_LENGTH` bytes of `Sha256(groth16_vk)`, when present in the input.
    pub vk_hash_tag: Option<[u8; VK_HASH_PREFIX_LENGTH]>,
    /// SP1 program exit code (SP1 v6+).
    pub exit_code: Option<[u8; 32]>,
    /// SP1 recursion verifier-key root (SP1 v6+).
    pub vk_root: Option<[u8; 32]>,
    /// SP1 proof nonce (SP1 v6+).
    pub proof_nonce: Option<[u8; 32]>,
}

impl From<Groth16Proof> for ParsedSp1Groth16Proof {
    fn from(proof: Groth16Proof) -> Self {
        Self {
            proof,
            vk_hash_tag: None,
            exit_code: None,
            vk_root: None,
            proof_nonce: None,
        }
    }
}

impl ParsedSp1Groth16Proof {
    /// Parse an SP1 Groth16 proof from any valid byte encoding produced by SP1 (or any prefix-
    /// pruned form thereof).
    ///
    /// The encoding is detected purely by length, matching one of:
    /// `[+vk_hash_prefix] [+v6_metadata] (compressed | uncompressed) raw_groth16_proof`.
    pub fn parse(raw_bytes: &[u8]) -> Result<Self, Groth16Error> {
        const C: usize = GROTH16_PROOF_COMPRESSED_SIZE;
        const U: usize = GROTH16_PROOF_UNCOMPRESSED_SIZE;
        const V: usize = VK_HASH_PREFIX_LENGTH;
        const M: usize = SP1_V6_PROOF_METADATA_LENGTH;

        // (has_vk_hash, has_metadata, is_compressed)
        let (has_vk_hash, has_metadata, is_compressed) = match raw_bytes.len() {
            C => (false, false, true),
            U => (false, false, false),
            l if l == V + C => (true, false, true),
            l if l == V + U => (true, false, false),
            l if l == M + C => (false, true, true),
            l if l == M + U => (false, true, false),
            l if l == V + M + C => (true, true, true),
            l if l == V + M + U => (true, true, false),
            _ => {
                return Err(Groth16Error::Serialization(
                    InvalidProofFormatError {
                        actual: raw_bytes.len(),
                    }
                    .into(),
                ));
            }
        };

        let mut cursor = raw_bytes;

        let vk_hash_tag = if has_vk_hash {
            let (head, rest) = cursor.split_at(V);
            cursor = rest;
            Some(<[u8; V]>::try_from(head).unwrap())
        } else {
            None
        };

        let (exit_code, vk_root, proof_nonce) = if has_metadata {
            let (head, rest) = cursor.split_at(M);
            cursor = rest;
            (
                Some(<[u8; 32]>::try_from(&head[..32]).unwrap()),
                Some(<[u8; 32]>::try_from(&head[32..64]).unwrap()),
                Some(<[u8; 32]>::try_from(&head[64..96]).unwrap()),
            )
        } else {
            (None, None, None)
        };

        let proof = if is_compressed {
            Groth16Proof::from_gnark_compressed_bytes(cursor)?
        } else {
            Groth16Proof::from_uncompressed_bytes(cursor)?
        };

        Ok(Self {
            proof,
            vk_hash_tag,
            exit_code,
            vk_root,
            proof_nonce,
        })
    }

    /// Validate the SP1 v6 metadata against the expected exit code and verifier key root, and
    /// return the algebraic public inputs derived from it (exit code and proof nonce).
    ///
    /// Returns an empty vector when no v6 metadata is present (SP1 v5 proofs, or proofs that have
    /// had the metadata pruned by the caller).
    pub fn extra_public_inputs(
        &self,
        expected_exit_code: [u8; 32],
        expected_vk_root: &[u8; 32],
    ) -> Result<Vec<Fr>, Groth16Error> {
        let (Some(exit_code), Some(vk_root), Some(proof_nonce)) =
            (self.exit_code, self.vk_root, self.proof_nonce)
        else {
            return Ok(Vec::new());
        };

        if exit_code != expected_exit_code {
            return Err(Groth16Error::ExitCodeMismatch);
        }

        if vk_root != *expected_vk_root {
            return Err(Groth16Error::VkeyRootMismatch);
        }

        Ok(vec![
            Fr::from_slice(&exit_code).map_err(SerializationError::from)?,
            Fr::from_slice(&proof_nonce).map_err(SerializationError::from)?,
        ])
    }
}
