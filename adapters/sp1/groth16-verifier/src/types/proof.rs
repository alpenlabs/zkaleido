use serde::{Deserialize, Serialize};

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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Groth16Proof {
    pub(crate) ar: SAffineG1,
    pub(crate) krs: SAffineG1,
    pub(crate) bs: SAffineG2,
}

impl Groth16Proof {
    /// Load a Groth16 proof from a byte slice in GNARK’s uncompressed format.
    ///
    /// The buffer is expected to be:
    /// - bytes 0..64:    uncompressed G1 point `A·R`
    /// - bytes 64..192:  uncompressed G2 point `B·S`
    /// - bytes 192..256: uncompressed G1 point `K·R·S`
    ///
    /// Returns a `Groth16Proof` containing affine points `(ar, bs, krs)`.
    pub(crate) fn load_from_gnark_bytes(buffer: &[u8]) -> Result<Groth16Proof, Groth16Error> {
        if buffer.len() != GROTH16_PROOF_LENGTH {
            return Err(Groth16Error::GeneralError(Error::InvalidData));
        }

        // Deserialize each component.
        let ar = SAffineG1(uncompressed_bytes_to_affine_g1(&buffer[..64])?);
        let bs = SAffineG2(uncompressed_bytes_to_affine_g2(&buffer[64..192])?);
        let krs = SAffineG1(uncompressed_bytes_to_affine_g1(&buffer[192..256])?);

        Ok(Groth16Proof { ar, bs, krs })
    }
}
