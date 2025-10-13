use crate::{
    error::{Error, Groth16Error},
    types::{
        g1::{uncompressed_bytes_to_affine_g1, SAffineG1},
        g2::{uncompressed_bytes_to_affine_g2, SAffineG2},
    },
};

/// Total byte length of a Groth16 proof when encoded as:
/// - 64 bytes (uncompressed G1): A · R
/// - 128 bytes (uncompressed G2): B · S
/// - 64 bytes (uncompressed G1): K · R · S
pub(crate) const GROTH16_PROOF_LENGTH: usize = 256;

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
            return Err(Groth16Error::GeneralError(Error::InvalidData));
        }

        // Deserialize each component.
        let ar = SAffineG1(uncompressed_bytes_to_affine_g1(&buffer[..64])?);
        let bs = SAffineG2(uncompressed_bytes_to_affine_g2(&buffer[64..192])?);
        let krs = SAffineG1(uncompressed_bytes_to_affine_g1(&buffer[192..256])?);

        Ok(Groth16Proof { ar, bs, krs })
    }

    /// Serialize to compressed bytes (160 bytes: 32 + 64 + 32 + 32).
    ///
    /// Layout:
    /// - bytes 0..32:    compressed G1 point `A·R`
    /// - bytes 32..96:   compressed G2 point `B·S`
    /// - bytes 96..128:  compressed G1 point `K·R·S` (first part)
    ///
    /// Note: This is more compact than GNARK's uncompressed format (256 bytes).
    pub fn to_compressed_bytes(&self) -> [u8; 160] {
        let mut bytes = [0u8; 160];

        // Serialize ar (G1 compressed: 32 bytes)
        bytes[0..32].copy_from_slice(&self.ar.to_compressed_bytes());

        // Serialize bs (G2 compressed: 64 bytes)
        bytes[32..96].copy_from_slice(&self.bs.to_compressed_bytes());

        // Serialize krs (G1 compressed: 32 bytes)
        bytes[96..128].copy_from_slice(&self.krs.to_compressed_bytes());

        bytes
    }

    /// Deserialize from compressed bytes (160 bytes).
    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, Groth16Error> {
        if bytes.len() != 160 {
            return Err(Groth16Error::GeneralError(Error::InvalidData));
        }

        let ar = SAffineG1::from_compressed_bytes(&bytes[0..32])?;
        let bs = SAffineG2::from_compressed_bytes(&bytes[32..96])?;
        let krs = SAffineG1::from_compressed_bytes(&bytes[96..128])?;

        Ok(Groth16Proof { ar, bs, krs })
    }

    /// Serialize to uncompressed bytes (256 bytes: 64 + 128 + 64).
    ///
    /// This is equivalent to GNARK's format.
    pub fn to_uncompressed_bytes(&self) -> [u8; 256] {
        let mut bytes = [0u8; 256];

        // Serialize ar (G1 uncompressed: 64 bytes)
        bytes[0..64].copy_from_slice(&self.ar.to_uncompressed_bytes());

        // Serialize bs (G2 uncompressed: 128 bytes)
        bytes[64..192].copy_from_slice(&self.bs.to_uncompressed_bytes());

        // Serialize krs (G1 uncompressed: 64 bytes)
        bytes[192..256].copy_from_slice(&self.krs.to_uncompressed_bytes());

        bytes
    }

    /// Deserialize from uncompressed bytes (256 bytes).
    ///
    /// This is an alias for [`load_from_gnark_bytes`](Self::load_from_gnark_bytes).
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, Groth16Error> {
        Self::load_from_gnark_bytes(bytes)
    }
}
