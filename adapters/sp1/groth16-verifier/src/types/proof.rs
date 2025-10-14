use crate::{
    error::{BufferLengthError, Groth16Error},
    types::{
        constant::{
            G1_COMPRESSED_SIZE, G1_UNCOMPRESSED_SIZE, G2_COMPRESSED_SIZE, G2_UNCOMPRESSED_SIZE,
            GROTH16_PROOF_COMPRESSED_SIZE, GROTH16_PROOF_UNCOMPRESSED_SIZE,
        },
        g1::SAffineG1,
        g2::SAffineG2,
    },
};

/// Total byte length of a Groth16 proof when encoded as:
/// - 64 bytes (uncompressed G1): A · R
/// - 128 bytes (uncompressed G2): B · S
/// - 64 bytes (uncompressed G1): K · R · S
pub(crate) const GROTH16_PROOF_LENGTH: usize = GROTH16_PROOF_UNCOMPRESSED_SIZE;

/// Proof for the Groth16 verification.
#[derive(Clone, Debug, PartialEq)]
pub struct Groth16Proof {
    pub(crate) ar: SAffineG1,
    pub(crate) krs: SAffineG1,
    pub(crate) bs: SAffineG2,
}

impl Groth16Proof {
    /// Load a Groth16 proof from a byte slice in GNARK's uncompressed format.
    ///
    /// The buffer is expected to be:
    /// - bytes 0..64:    uncompressed G1 point `A·R`
    /// - bytes 64..192:  uncompressed G2 point `B·S`
    /// - bytes 192..256: uncompressed G1 point `K·R·S`
    ///
    /// Returns a `Groth16Proof` containing affine points `(ar, bs, krs)`.
    pub fn load_from_gnark_bytes(buffer: &[u8]) -> Result<Groth16Proof, Groth16Error> {
        if buffer.len() != GROTH16_PROOF_LENGTH {
            return Err(Groth16Error::Serialization(
                BufferLengthError {
                    expected: GROTH16_PROOF_LENGTH,
                    actual: buffer.len(),
                }
                .into(),
            ));
        }

        // Deserialize each component.
        let ar = SAffineG1::from_uncompressed_bytes(&buffer[..G1_UNCOMPRESSED_SIZE])?;
        let bs = SAffineG2::from_uncompressed_bytes(
            &buffer[G1_UNCOMPRESSED_SIZE..G1_UNCOMPRESSED_SIZE + G2_UNCOMPRESSED_SIZE],
        )?;
        let krs = SAffineG1::from_uncompressed_bytes(
            &buffer[G1_UNCOMPRESSED_SIZE + G2_UNCOMPRESSED_SIZE..GROTH16_PROOF_UNCOMPRESSED_SIZE],
        )?;

        Ok(Groth16Proof { ar, bs, krs })
    }

    /// Deserialize from GNARK-compressed bytes (160 bytes).
    pub fn from_gnark_compressed_bytes(bytes: &[u8]) -> Result<Self, Groth16Error> {
        if bytes.len() != GROTH16_PROOF_COMPRESSED_SIZE {
            return Err(Groth16Error::Serialization(
                BufferLengthError {
                    expected: GROTH16_PROOF_COMPRESSED_SIZE,
                    actual: bytes.len(),
                }
                .into(),
            ));
        }

        let ar = SAffineG1::from_gnark_compressed_bytes(&bytes[0..G1_COMPRESSED_SIZE])?;
        let bs = SAffineG2::from_gnark_compressed_bytes(
            &bytes[G1_COMPRESSED_SIZE..G1_COMPRESSED_SIZE + G2_COMPRESSED_SIZE],
        )?;
        let krs = SAffineG1::from_gnark_compressed_bytes(
            &bytes[G1_COMPRESSED_SIZE + G2_COMPRESSED_SIZE..GROTH16_PROOF_COMPRESSED_SIZE],
        )?;

        Ok(Groth16Proof { ar, bs, krs })
    }

    /// Serialize to GNARK-compressed bytes (160 bytes: 32 + 64 + 64).
    ///
    /// Uses the GNARK compression scheme.
    ///
    /// Layout:
    /// - bytes 0..32:    GNARK-compressed G1 point `A·R`
    /// - bytes 32..96:   GNARK-compressed G2 point `B·S`
    /// - bytes 96..160:  GNARK-compressed G1 point `K·R·S`
    ///
    /// Note: This is more compact than GNARK's uncompressed format (256 bytes).
    pub fn to_gnark_compressed_bytes(&self) -> [u8; GROTH16_PROOF_COMPRESSED_SIZE] {
        let mut bytes = [0u8; GROTH16_PROOF_COMPRESSED_SIZE];

        // Serialize ar (G1 GNARK-compressed)
        bytes[0..G1_COMPRESSED_SIZE].copy_from_slice(&self.ar.to_gnark_compressed_bytes());

        // Serialize bs (G2 GNARK-compressed)
        bytes[G1_COMPRESSED_SIZE..G1_COMPRESSED_SIZE + G2_COMPRESSED_SIZE]
            .copy_from_slice(&self.bs.to_gnark_compressed_bytes());

        // Serialize krs (G1 GNARK-compressed)
        bytes[G1_COMPRESSED_SIZE + G2_COMPRESSED_SIZE..GROTH16_PROOF_COMPRESSED_SIZE]
            .copy_from_slice(&self.krs.to_gnark_compressed_bytes());

        bytes
    }

    /// Serialize to uncompressed bytes (256 bytes: 64 + 128 + 64).
    ///
    /// This is equivalent to GNARK's format.
    pub fn to_uncompressed_bytes(&self) -> [u8; GROTH16_PROOF_UNCOMPRESSED_SIZE] {
        let mut bytes = [0u8; GROTH16_PROOF_UNCOMPRESSED_SIZE];

        // Serialize ar (G1 uncompressed)
        bytes[0..G1_UNCOMPRESSED_SIZE].copy_from_slice(&self.ar.to_uncompressed_bytes());

        // Serialize bs (G2 uncompressed)
        bytes[G1_UNCOMPRESSED_SIZE..G1_UNCOMPRESSED_SIZE + G2_UNCOMPRESSED_SIZE]
            .copy_from_slice(&self.bs.to_uncompressed_bytes());

        // Serialize krs (G1 uncompressed)
        bytes[G1_UNCOMPRESSED_SIZE + G2_UNCOMPRESSED_SIZE..GROTH16_PROOF_UNCOMPRESSED_SIZE]
            .copy_from_slice(&self.krs.to_uncompressed_bytes());

        bytes
    }

    /// Deserialize from uncompressed bytes (256 bytes).
    ///
    /// This is an alias for [`load_from_gnark_bytes`](Self::load_from_gnark_bytes).
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, Groth16Error> {
        Self::load_from_gnark_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_test_proof() -> Groth16Proof {
        // Load a real proof from a test file
        let program_id_hex = "00eb7fd5709e4b833db86054ba4acca001a3aa5f18b7e7d0d96d0f1d340b4e34";
        let proof_file = format!("./proofs/fibonacci_sp1_0x{}.proof.bin", program_id_hex);
        let receipt = zkaleido::ProofReceiptWithMetadata::load(proof_file)
            .unwrap()
            .receipt()
            .clone();

        // Skip the 4-byte VK hash prefix
        let proof_bytes = &receipt.proof().as_bytes()[4..];
        Groth16Proof::from_uncompressed_bytes(proof_bytes).unwrap()
    }

    #[test]
    fn test_proof_compressed_roundtrip() {
        let proof = load_test_proof();

        // Compress and decompress
        let compressed = proof.to_gnark_compressed_bytes();
        let decompressed = Groth16Proof::from_gnark_compressed_bytes(&compressed).unwrap();

        assert_eq!(proof, decompressed);
    }

    #[test]
    fn test_proof_uncompressed_roundtrip() {
        let proof = load_test_proof();

        // Convert to uncompressed and back
        let uncompressed = proof.to_uncompressed_bytes();
        let recovered = Groth16Proof::from_uncompressed_bytes(&uncompressed).unwrap();

        assert_eq!(proof, recovered);
    }
}
