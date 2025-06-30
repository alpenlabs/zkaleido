use zkaleido_bn_groth16_types::{Groth16Proof, SAffineG1, SAffineG2};

use crate::{
    error::{Error, Groth16Error},
    gnark_conversion::{g1::uncompressed_bytes_to_affine_g1, g2::uncompressed_bytes_to_affine_g2},
};

/// Total byte length of a Groth16 proof when encoded as:
/// - 64 bytes (uncompressed G1): A · R
/// - 128 bytes (uncompressed G2): B · S
/// - 64 bytes (uncompressed G1): K · R · S
pub(crate) const GROTH16_PROOF_LENGTH: usize = 256;

/// Load a Groth16 proof from a byte slice in GNARK’s uncompressed format.
///
/// The buffer is expected to be:
/// - bytes 0..64:    uncompressed G1 point `A·R`
/// - bytes 64..192:  uncompressed G2 point `B·S`
/// - bytes 192..256: uncompressed G1 point `K·R·S`
///
/// Returns a `Groth16Proof` containing affine points `(ar, bs, krs)`.
pub(crate) fn load_proof_from_gnark_bytes(buffer: &[u8]) -> Result<Groth16Proof, Groth16Error> {
    if buffer.len() != GROTH16_PROOF_LENGTH {
        return Err(Groth16Error::GeneralError(Error::InvalidData));
    }

    // Deserialize each component.
    let ar = SAffineG1(uncompressed_bytes_to_affine_g1(&buffer[..64])?);
    let bs = SAffineG2(uncompressed_bytes_to_affine_g2(&buffer[64..192])?);
    let krs = SAffineG1(uncompressed_bytes_to_affine_g1(&buffer[192..256])?);

    Ok(Groth16Proof { ar, bs, krs })
}
