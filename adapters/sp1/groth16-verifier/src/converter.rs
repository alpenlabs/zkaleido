use std::io::Read;

use bn::{
    arith::{U256, U512},
    AffineG1, AffineG2, Fq, Fq2, G1, G2,
};

use crate::{
    constants::{
        COMPRESSED_INFINITY, COMPRESSED_NEGATIVE, COMPRESSED_POSITIVE, GROTH16_PROOF_LENGTH, MASK,
    },
    error::{Error, Groth16Error},
    types::{Groth16G1, Groth16G2, Groth16Proof, Groth16VerifyingKey},
};

fn convert_from_gnark_compressed_to_bn_compressed_g1_bytes(buf: &[u8]) -> Result<[u8; 33], Error> {
    if buf.len() != 32 {
        return Err(Error::InvalidXLength);
    }

    let flag = buf[0] & MASK;
    let mut result = [0u8; 33];

    // Set sign byte
    result[0] = match flag {
        COMPRESSED_POSITIVE => 2,
        COMPRESSED_NEGATIVE => 3,
        COMPRESSED_INFINITY => return Err(Error::InvalidPoint), // Handle infinity case separately
        _ => return Err(Error::InvalidPoint),
    };

    // Copy x-coordinate with flags cleared
    result[1..].copy_from_slice(buf);
    result[1] &= !MASK; // Clear the flag bits

    Ok(result)
}

fn convert_from_gnark_compressed_to_bn_compressed_g2_bytes(
    bytes_64: &[u8],
) -> Result<[u8; 65], Error> {
    if bytes_64.len() != 64 {
        return Err(Error::InvalidXLength);
    }

    let flag = bytes_64[0] & MASK;
    let mut result = [0u8; 65];

    // Set sign byte
    result[0] = match flag {
        COMPRESSED_POSITIVE => 10,
        COMPRESSED_NEGATIVE => 11,
        COMPRESSED_INFINITY => return Err(Error::InvalidPoint), // Handle infinity case separately
        _ => return Err(Error::InvalidPoint),
    };

    // Copy out c₁‐bytes (first 32 bytes) and mask out the two MSBs because they were used for
    // gnark's flag.
    let mut c1_bytes = [0u8; 32];
    c1_bytes.copy_from_slice(&bytes_64[0..32]);
    c1_bytes[0] &= !MASK; // clear the two high‐bits

    // c₀ is just bytes_64[32..64], no flag bits there.
    let mut c0_bytes = [0u8; 32];
    c0_bytes.copy_from_slice(&bytes_64[32..64]);

    // Step 4. Turn both 32‐byte big‐endian limbs into U256
    let c1_u256 = U256::from_slice(&c1_bytes).map_err(|_| Error::InvalidData)?;
    let c0_u256 = U256::from_slice(&c0_bytes).map_err(|_| Error::InvalidData)?;

    let fq_modulus: U256 = Fq::modulus();
    let u512: U512 = U512::new(&c1_u256, &c0_u256, &fq_modulus);

    let limbs: [u128; 4] = u512.0;
    for (i, limb) in limbs.iter().enumerate() {
        // byte‐offset within the 64‐byte big‐endian field
        let offset_within_64 = (3 - i) * 16;
        // BUT we must shift by +1 to account for result[0] = sign.
        let dest_offset = 1 + offset_within_64;
        result[dest_offset..dest_offset + 16].copy_from_slice(&limb.to_be_bytes());
    }

    Ok(result)
}

/// Converts a compressed G1 point to an G1 point.
///
/// Asserts that the compressed point is represented as a single fq element: the x coordinate
/// of the point. The y coordinate is then computed from the x coordinate. The final point
/// is not checked to be on the curve for efficiency.
pub(crate) fn uncompress_g1(buf: &[u8]) -> Result<G1, Error> {
    let buf = convert_from_gnark_compressed_to_bn_compressed_g1_bytes(buf)?;
    G1::from_compressed(&buf).map_err(Error::Curve)
}

fn to_g1_affine(g1: G1) -> Result<AffineG1, Error> {
    AffineG1::from_jacobian(g1).ok_or(Error::InvalidPoint)
}

fn to_g2_affine(g2: G2) -> Result<AffineG2, Error> {
    AffineG2::from_jacobian(g2).ok_or(Error::InvalidPoint)
}

/// Converts a compressed G2 point to an AffineG2 point.
///
/// Asserts that the compressed point is represented as a single fq2 element: the x coordinate
/// of the point.
/// Then, gets the y coordinate from the x coordinate.
/// For efficiency, this function does not check that the final point is on the curve.
pub(crate) fn uncompress_g2(buf: &[u8]) -> Result<G2, Error> {
    let buf = convert_from_gnark_compressed_to_bn_compressed_g2_bytes(buf)?;
    G2::from_compressed(&buf).map_err(Error::Curve)
}

/// Converts an uncompressed G1 point to an AffineG1 point.
///
/// Asserts that the affine point is represented as two fq elements.
pub(crate) fn uncompressed_bytes_to_affine_g1(buf: &[u8]) -> Result<AffineG1, Error> {
    if buf.len() != 64 {
        return Err(Error::InvalidXLength);
    };

    let (x_bytes, y_bytes) = buf.split_at(32);

    let x = Fq::from_slice(x_bytes).map_err(Error::Field)?;
    let y = Fq::from_slice(y_bytes).map_err(Error::Field)?;
    AffineG1::new(x, y).map_err(Error::Group)
}

/// Converts an uncompressed G2 point to an AffineG2 point.
///
/// Asserts that the affine point is represented as two fq2 elements.
pub(crate) fn uncompressed_bytes_to_g2_point(buf: &[u8]) -> Result<AffineG2, Error> {
    if buf.len() != 128 {
        return Err(Error::InvalidXLength);
    }

    let (x_bytes, y_bytes) = buf.split_at(64);
    let (x1_bytes, x0_bytes) = x_bytes.split_at(32);
    let (y1_bytes, y0_bytes) = y_bytes.split_at(32);

    let x1 = Fq::from_slice(x1_bytes).map_err(Error::Field)?;
    let x0 = Fq::from_slice(x0_bytes).map_err(Error::Field)?;
    let y1 = Fq::from_slice(y1_bytes).map_err(Error::Field)?;
    let y0 = Fq::from_slice(y0_bytes).map_err(Error::Field)?;

    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);

    AffineG2::new(x, y).map_err(Error::Group)
}

/// Load the Groth16 proof from the given byte slice.
///
/// The byte slice is represented as 2 uncompressed g1 points, and one uncompressed g2 point,
/// as outputted from Gnark.
pub(crate) fn load_groth16_proof_from_bytes(buffer: &[u8]) -> Result<Groth16Proof, Groth16Error> {
    if buffer.len() < GROTH16_PROOF_LENGTH {
        return Err(Groth16Error::GeneralError(Error::InvalidData));
    }

    let ar = uncompressed_bytes_to_affine_g1(&buffer[..64])?;
    let bs = uncompressed_bytes_to_g2_point(&buffer[64..192])?;
    let krs = uncompressed_bytes_to_affine_g1(&buffer[192..256])?;

    Ok(Groth16Proof { ar, bs, krs })
}

/// Load the Groth16 verification key from the given byte slice.
///
/// The gnark verification key includes a lot of extraneous information. We only extract the
/// necessary elements to verify a proof.
pub(crate) fn load_groth16_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<Groth16VerifyingKey, Groth16Error> {
    // We don't need to check each compressed point because the Groth16 vkey is a public constant
    // that doesn't usually change. The party using the Groth16 vkey will usually clearly know
    // how the vkey was generated.
    let g1_alpha = uncompress_g1(&buffer[..32])?;
    let g2_beta = uncompress_g2(&buffer[64..128])?;
    let g2_gamma = uncompress_g2(&buffer[128..192])?;
    let g2_delta = uncompress_g2(&buffer[224..288])?;

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut k = Vec::new();
    let mut offset = 292;
    for _ in 0..num_k {
        let point = to_g1_affine(uncompress_g1(&buffer[offset..offset + 32])?)?;
        k.push(point);
        offset += 32;
    }

    Ok(Groth16VerifyingKey {
        g1: Groth16G1 {
            alpha: to_g1_affine(g1_alpha)?,
            k,
        },
        g2: Groth16G2 {
            beta: to_g2_affine(-g2_beta)?,
            gamma: to_g2_affine(g2_gamma)?,
            delta: to_g2_affine(g2_delta)?,
        },
    })
}

#[cfg(test)]
mod tests {
    use sp1_verifier::GROTH16_VK_BYTES;

    use super::*;

    #[test]
    fn test_load_g16_key() {
        match load_groth16_verifying_key_from_bytes(&GROTH16_VK_BYTES) {
            Ok(_) => {}
            Err(e) => println!("{}", e),
        }
    }
}
