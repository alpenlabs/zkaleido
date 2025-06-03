use core::cmp::Ordering;

use bn::{AffineG1, AffineG2, FieldError, Fq, Fq2};
use num_bigint::BigUint;

use crate::{
    constants::{CompressedPointFlag, MASK},
    error::Error,
};

/// Deserializes an Fq element from a buffer.
///
/// If this Fq element is part of a compressed point, the flag that indicates the sign of the
/// y coordinate is also returned.
pub(crate) fn deserialize_with_flags(buf: &[u8]) -> Result<(Fq, CompressedPointFlag), Error> {
    if buf.len() != 32 {
        return Err(Error::InvalidXLength);
    };

    let m_data = buf[0] & MASK;
    if m_data == u8::from(CompressedPointFlag::Infinity) {
        // Checks if the first byte is zero after masking AND the rest of the bytes are zero.
        if buf[0] & !MASK == 0 && buf[1..].iter().all(|&b| b == 0) {
            return Err(Error::InvalidPoint);
        }
        Ok((Fq::zero(), CompressedPointFlag::Infinity))
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !MASK;

        let x = fq_from_be_bytes_mod_order(&x_bytes).expect("Failed to convert x bytes to Fq");

        Ok((x, m_data.into()))
    }
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
