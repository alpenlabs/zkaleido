use std::cmp::Ordering;

use bn::{AffineG1, AffineG2, Fq, Fq2, Group, G1, G2};

use crate::{
    error::{Error, Groth16Error},
    types::{Groth16G1, Groth16G2, Groth16Proof, Groth16VerifyingKey},
};

/// Gnark (and arkworks) use the 2 most significant bits to encode the flag for a compressed
/// G1 point.
/// https://github.com/Consensys/gnark-crypto/blob/a7d721497f2a98b1f292886bb685fd3c5a90f930/ecc/bn254/marshal.go#L32-L42
pub(crate) const MASK: u8 = 0b11 << 6;

/// The flags for a positive, negative, or infinity compressed point.
pub(crate) const COMPRESSED_POSITIVE: u8 = 0b10 << 6;
pub(crate) const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
pub(crate) const COMPRESSED_INFINITY: u8 = 0b01 << 6;

pub(crate) const GROTH16_PROOF_LENGTH: usize = 256;

fn compressed_bytes_to_affine_g1(buf: &[u8]) -> Result<AffineG1, Error> {
    if buf.len() != 32 {
        return Err(Error::InvalidXLength);
    }

    let flag = buf[0] & MASK;

    // Copy x-coordinate with flags cleared
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(buf);
    x_bytes[0] &= !MASK;

    // Create Fq from reduced x-coordinate
    let x_fq = Fq::from_slice(&x_bytes).map_err(|_| Error::InvalidPoint)?;

    // Compute both possible y-coordinates
    let (y, neg_y) = get_ys_from_x_g1(x_fq)?;
    match flag {
        COMPRESSED_NEGATIVE => AffineG1::new(x_fq, neg_y).map_err(Error::Group),
        COMPRESSED_POSITIVE => AffineG1::new(x_fq, y).map_err(Error::Group),
        _ => Err(Error::InvalidData),
    }
}

fn compressed_bytes_to_affine_g2(buf: &[u8]) -> Result<AffineG2, Error> {
    if buf.len() != 64 {
        return Err(Error::InvalidXLength);
    }

    let flag = buf[0] & MASK;

    if flag == COMPRESSED_INFINITY {
        return AffineG2::from_jacobian(G2::one()).ok_or(Error::InvalidData);
    }

    // Copy x-coordinate with flags cleared
    let mut x1_bytes = [0u8; 32];
    x1_bytes.copy_from_slice(&buf[0..32]);
    x1_bytes[0] &= !MASK;
    let x1 = Fq::from_slice(&x1_bytes).map_err(Error::Field)?;

    let mut x0_bytes = [0u8; 32];
    x0_bytes.copy_from_slice(&buf[32..64]);
    let x0 = Fq::from_slice(&x0_bytes).map_err(Error::Field)?;

    // Create Fq2 from reduced x-coordinate
    let x_fq = Fq2::new(x0, x1);

    let (y, neg_y) = get_ys_from_x_g2(x_fq)?;
    match flag {
        COMPRESSED_NEGATIVE => AffineG2::new(x_fq, neg_y).map_err(Error::Group),
        COMPRESSED_POSITIVE => AffineG2::new(x_fq, y).map_err(Error::Group),
        _ => Err(Error::InvalidData),
    }
}

fn get_ys_from_x_g2(x: Fq2) -> Result<(Fq2, Fq2), Error> {
    // Compute both possible y-coordinates
    let y_squared = (x * x * x) + G2::b();
    let y = y_squared.sqrt().ok_or(Error::InvalidPoint)?;
    let neg_y = -y;

    // Compare lexicographically: imaginary part first, then real part
    let is_y_less_than_neg_y = match y
        .imaginary()
        .into_u256()
        .cmp(&neg_y.imaginary().into_u256())
    {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => y.real().into_u256() < neg_y.real().into_u256(),
    };

    if is_y_less_than_neg_y {
        Ok((y, neg_y))
    } else {
        Ok((neg_y, y))
    }
}

fn get_ys_from_x_g1(x: Fq) -> Result<(Fq, Fq), Error> {
    // Compute both possible y-coordinates
    let y_squared = (x * x * x) + G1::b();
    let y = y_squared.sqrt().ok_or(Error::InvalidPoint)?;
    let neg_y = -y;

    if y.into_u256() < neg_y.into_u256() {
        Ok((y, neg_y))
    } else {
        Ok((neg_y, y))
    }
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
    let g1_alpha = compressed_bytes_to_affine_g1(&buffer[..32])?;
    let g2_beta = compressed_bytes_to_affine_g2(&buffer[64..128])?;
    let g2_gamma = compressed_bytes_to_affine_g2(&buffer[128..192])?;
    let g2_delta = compressed_bytes_to_affine_g2(&buffer[224..288])?;

    let neg_g2_beta = AffineG2::from_jacobian(-G2::from(g2_beta)).ok_or(Error::InvalidPoint)?;

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut k = Vec::new();
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

#[cfg(test)]
mod tests {

    use sp1_verifier::GROTH16_VK_BYTES;

    use super::*;

    #[test]
    fn test_load_g16_key() {
        // dbg!(&GROTH16_VK_BYTES.to_vec());
        let mut be = [0u8; 32];
        let vk = load_groth16_verifying_key_from_bytes(&GROTH16_VK_BYTES).unwrap();
        vk.g1.alpha.x().to_big_endian(&mut be).unwrap();
        println!("alpha x{:?}", be);
        vk.g1.alpha.y().to_big_endian(&mut be).unwrap();
        println!("alpha y{:?}", be);

        for k in vk.g1.k {
            k.x().to_big_endian(&mut be).unwrap();
            println!("kx{:?}", be);
            k.y().to_big_endian(&mut be).unwrap();
            println!("ky{:?}", be);
        }

        vk.g2.beta.x().real().to_big_endian(&mut be).unwrap();
        println!("beta x real{:?}", be);
        vk.g2.beta.x().imaginary().to_big_endian(&mut be).unwrap();
        println!("beta y im{:?}", be);
        vk.g2.beta.y().real().to_big_endian(&mut be).unwrap();
        println!("beta y real{:?}", be);
        vk.g2.beta.y().imaginary().to_big_endian(&mut be).unwrap();
        println!("beta y im{:?}", be);

        vk.g2.delta.x().real().to_big_endian(&mut be).unwrap();
        println!("delta x real{:?}", be);
        vk.g2.delta.x().imaginary().to_big_endian(&mut be).unwrap();
        println!("delta x im{:?}", be);
        vk.g2.delta.y().real().to_big_endian(&mut be).unwrap();
        println!("delta y real {:?}", be);
        vk.g2.delta.y().imaginary().to_big_endian(&mut be).unwrap();
        println!("delta y im{:?}", be);

        vk.g2.gamma.x().real().to_big_endian(&mut be).unwrap();
        println!("gamma x real{:?}", be);
        vk.g2.gamma.x().imaginary().to_big_endian(&mut be).unwrap();
        println!("gamma x im{:?}", be);
        vk.g2.gamma.y().real().to_big_endian(&mut be).unwrap();
        println!("gamma y real{:?}", be);
        vk.g2.gamma.y().imaginary().to_big_endian(&mut be).unwrap();
        println!("gamma y im{:?}", be);
    }

    #[test]
    fn test_fq() {
        let slice = &[
            45, 77, 154, 167, 227, 2, 217, 223, 65, 116, 157, 85, 7, 148, 157, 5, 219, 234, 51,
            251, 177, 108, 100, 59, 34, 245, 153, 162, 190, 109, 242, 226,
        ];
        let mut be = [0u8; 32];
        let fq = Fq::from_slice(slice).unwrap();
        fq.to_big_endian(&mut be).unwrap();
        dbg!(fq);
        println!("{:?}", be);
    }
}
