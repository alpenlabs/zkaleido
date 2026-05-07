//! Parsing for the on-wire byte encoding of an SP1 Groth16 proof.
//!
//! The full SP1 wire format is:
//!
//! ```text
//! [ vk_hash_prefix || exit_code || vk_root || proof_nonce || uncompressed_groth16_proof_bytes ]
//! ```
//!
//! On top of that, this module accepts encodings in which some of the fields are omitted. This
//! optionality allows to cut down the wire footprint of proofs. The smallest accepted encoding is
//! the bare GNARK-compressed proof with no other fields at all. Which fields may be omitted is
//! constrained: fields appearing earlier are "more optional" — the closer to `proof`, the more
//! likely it is to be kept. The valid encodings are therefore:
//!
//! - `proof`
//! - `proof_nonce || proof`
//! - `vk_root || proof_nonce || proof`
//! - `exit_code || vk_root || proof_nonce || proof`
//! - `vk_hash_prefix || exit_code || vk_root || proof_nonce || proof`
//!
//! The raw proof itself is either GNARK-compressed or uncompressed; both lengths are accepted.

use crate::{
    error::{InvalidProofFormatError, Sp1Groth16Error},
    types::{
        constant::{
            GROTH16_PROOF_COMPRESSED_SIZE, GROTH16_PROOF_UNCOMPRESSED_SIZE, VK_HASH_PREFIX_LENGTH,
        },
        proof::Groth16Proof,
    },
};

/// In-memory form of an SP1 Groth16 proof together with any prefix fields recovered from its
/// byte encoding.
///
/// See the module-level docs for the on-wire format and which prefix fields are optional.
/// Each `Option<...>` field below is `Some` iff that field was present in the parsed bytes;
/// whether a missing field is an error, gets a default, or is simply ignored is decided
/// downstream by [`SP1Groth16Verifier::verify_parsed`](crate::SP1Groth16Verifier::verify_parsed).
#[derive(Clone, Debug)]
pub struct Sp1Groth16Proof {
    /// First `VK_HASH_PREFIX_LENGTH` bytes of `Sha256(groth16_vk)`, when present in the input.
    pub vk_hash_tag: Option<[u8; VK_HASH_PREFIX_LENGTH]>,
    /// SP1 program exit code (SP1 v6+).
    pub exit_code: Option<[u8; 32]>,
    /// SP1 recursion verifier-key root (SP1 v6+).
    pub vk_root: Option<[u8; 32]>,
    /// SP1 proof nonce (SP1 v6+).
    pub proof_nonce: Option<[u8; 32]>,
    /// The underlying Groth16 proof.
    pub proof: Groth16Proof,
}

impl From<Groth16Proof> for Sp1Groth16Proof {
    fn from(proof: Groth16Proof) -> Self {
        Self {
            vk_hash_tag: None,
            exit_code: None,
            vk_root: None,
            proof_nonce: None,
            proof,
        }
    }
}

impl Sp1Groth16Proof {
    /// Parse an SP1 Groth16 proof from any of the byte encodings listed in the module-level
    /// docs.
    ///
    /// Detection is purely by length: `raw_bytes.len()` must equal exactly one of the ten
    /// valid combinations (five prefix shapes × {compressed, uncompressed} raw proof). Any
    /// other length yields `Sp1Groth16Error::Serialization` wrapping an `InvalidProofFormatError`;
    /// a length match followed by a malformed raw proof yields the parse error from
    /// [`Groth16Proof::from_gnark_compressed_bytes`] /
    /// [`Groth16Proof::from_uncompressed_bytes`].
    ///
    /// This function does no semantic validation — see [`Sp1Groth16Proof`] for what
    /// recovered fields mean.
    pub fn parse(raw_bytes: &[u8]) -> Result<Self, Sp1Groth16Error> {
        const C: usize = GROTH16_PROOF_COMPRESSED_SIZE;
        const U: usize = GROTH16_PROOF_UNCOMPRESSED_SIZE;
        const V: usize = VK_HASH_PREFIX_LENGTH;

        // Number of prefix fields present, counting from the proof outward:
        //   0 = proof only
        //   1 = proof_nonce
        //   2 = vk_root, proof_nonce
        //   3 = exit_code, vk_root, proof_nonce
        //   4 = vk_hash_tag, exit_code, vk_root, proof_nonce
        let (prefix_depth, is_compressed) = match raw_bytes.len() {
            l if l == C => (0u8, true),
            l if l == U => (0, false),
            l if l == 32 + C => (1, true),
            l if l == 32 + U => (1, false),
            l if l == 64 + C => (2, true),
            l if l == 64 + U => (2, false),
            l if l == 96 + C => (3, true),
            l if l == 96 + U => (3, false),
            l if l == V + 96 + C => (4, true),
            l if l == V + 96 + U => (4, false),
            _ => {
                return Err(Sp1Groth16Error::Serialization(
                    InvalidProofFormatError {
                        actual: raw_bytes.len(),
                    }
                    .into(),
                ));
            }
        };

        let mut cursor = raw_bytes;

        let vk_hash_tag = (prefix_depth >= 4).then(|| {
            let (head, rest) = cursor.split_at(V);
            cursor = rest;
            <[u8; V]>::try_from(head).unwrap()
        });

        let exit_code = (prefix_depth >= 3).then(|| {
            let (head, rest) = cursor.split_at(32);
            cursor = rest;
            <[u8; 32]>::try_from(head).unwrap()
        });

        let vk_root = (prefix_depth >= 2).then(|| {
            let (head, rest) = cursor.split_at(32);
            cursor = rest;
            <[u8; 32]>::try_from(head).unwrap()
        });

        let proof_nonce = (prefix_depth >= 1).then(|| {
            let (head, rest) = cursor.split_at(32);
            cursor = rest;
            <[u8; 32]>::try_from(head).unwrap()
        });

        let proof = if is_compressed {
            Groth16Proof::from_gnark_compressed_bytes(cursor)?
        } else {
            Groth16Proof::from_uncompressed_bytes(cursor)?
        };

        Ok(Self {
            vk_hash_tag,
            exit_code,
            vk_root,
            proof_nonce,
            proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use zkaleido::ProofReceiptWithMetadata;

    use crate::Sp1Groth16Proof;

    #[test]
    fn test_parse_proof() {
        let receipt =
            ProofReceiptWithMetadata::load("./proofs/fibonacci_SP1_v6.1.0.proof.bin").unwrap();
        let res = Sp1Groth16Proof::parse(receipt.receipt().proof().as_bytes());
        assert!(res.is_ok());
        let proof = res.unwrap();
        assert!(proof.vk_hash_tag.is_some());
        assert!(proof.exit_code.is_some());
        assert!(proof.vk_root.is_some());
        assert!(proof.proof_nonce.is_some());
    }
}
