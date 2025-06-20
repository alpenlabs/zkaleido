//! Utilities for converting byte representations of Groth16 proofs and verifying keys
//! into affine curve points using the BN254 elliptic curve.
//!
//! This module handles both compressed and uncompressed representations of G1 and G2 points,
//! mapping them into `AffineG1` and `AffineG2` types from the `bn` crate. It also provides
//! functions to load Groth16 proofs and verification keys from raw byte slices, as output by Gnark.

use bn::{AffineG2, G2};

use crate::{
    error::{Error, Groth16Error},
    gnark_conversion::{
        g1::{compressed_bytes_to_affine_g1, uncompressed_bytes_to_affine_g1},
        g2::{compressed_bytes_to_affine_g2, uncompressed_bytes_to_g2_point},
    },
    types::{Groth16G1, Groth16G2, Groth16Proof, Groth16VerifyingKey},
};
mod constant;
mod g1;
mod g2;

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
pub(crate) fn load_groth16_proof_from_bytes(buffer: &[u8]) -> Result<Groth16Proof, Groth16Error> {
    if buffer.len() < GROTH16_PROOF_LENGTH {
        return Err(Groth16Error::GeneralError(Error::InvalidData));
    }

    // Deserialize each component.
    let ar = uncompressed_bytes_to_affine_g1(&buffer[..64])?;
    let bs = uncompressed_bytes_to_g2_point(&buffer[64..192])?;
    let krs = uncompressed_bytes_to_affine_g1(&buffer[192..256])?;

    Ok(Groth16Proof { ar, bs, krs })
}

/// Load a Groth16 verifying key from the GNARK‐style compressed byte slice.
pub(crate) fn load_groth16_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<Groth16VerifyingKey, Groth16Error> {
    // Parse G1 alpha (compressed).
    let g1_alpha = compressed_bytes_to_affine_g1(&buffer[..32])?;

    // Parse G2 beta, gamma, delta (compressed).
    let g2_beta = compressed_bytes_to_affine_g2(&buffer[64..128])?;
    let g2_gamma = compressed_bytes_to_affine_g2(&buffer[128..192])?;
    let g2_delta = compressed_bytes_to_affine_g2(&buffer[224..288])?;

    // Negate beta for the verifier’s purpose.
    let neg_g2_beta = AffineG2::from_jacobian(-G2::from(g2_beta)).ok_or(Error::InvalidPoint)?;

    // Read the number of K points (u32, big‐endian).
    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut k = Vec::with_capacity(num_k as usize);
    let mut offset = 292;
    for _ in 0..num_k {
        let point = compressed_bytes_to_affine_g1(&buffer[offset..offset + 32])?;
        k.push(point);
        offset += 32;
    }

    Ok(Groth16VerifyingKey {
        g1: Groth16G1 { alpha: g1_alpha, k },
        g2: Groth16G2 {
            beta: neg_g2_beta,
            gamma: g2_gamma,
            delta: g2_delta,
        },
    })
}
