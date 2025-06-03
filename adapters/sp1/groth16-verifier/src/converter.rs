use core::cmp::Ordering;

use bn::{AffineG1, AffineG2, FieldError, Fq, Fq2, Group, G1};
use num_bigint::BigUint;

use crate::{
    constants::{
        CompressedPointFlag, COMPRESSED_INFINITY, COMPRESSED_NEGATIVE, COMPRESSED_POSITIVE, MASK,
    },
    error::Error,
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

/// Converts a compressed G1 point to an AffineG1 point.
///
/// Asserts that the compressed point is represented as a single fq element: the x coordinate
/// of the point. The y coordinate is then computed from the x coordinate. The final point
/// is not checked to be on the curve for efficiency.
pub(crate) fn compressed_x_to_g1_point(buf: &[u8]) -> Result<AffineG1, Error> {
    let buf = convert_from_gnark_compressed_to_bn_compressed_g1_bytes(buf)?;
    let g1 = G1::from_compressed(&buf).map_err(Error::Curve)?;
    AffineG1::from_jacobian(g1).ok_or(Error::InvalidPoint)
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

fn fq_from_be_bytes_mod_order(bytes: &[u8]) -> Result<Fq, FieldError> {
    let mut modulus_bytes = [0u8; 32];
    Fq::modulus().to_big_endian(&mut modulus_bytes).unwrap();
    let modulus = BigUint::from_bytes_be(&modulus_bytes);
    let num = BigUint::from_bytes_be(bytes) % modulus;
    Fq::from_slice(&num.to_bytes_be())
}
