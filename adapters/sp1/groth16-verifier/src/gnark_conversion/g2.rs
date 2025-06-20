use std::cmp::Ordering;

use bn::{AffineG2, Fq, Fq2, Group, G2};

use crate::{
    gnark_conversion::constant::{COMPRESSED_INFINITY, COMPRESSED_NEGATIVE, COMPRESSED_POSITIVE, MASK},
    error::Error,
};

/// Convert a 64-byte compressed G2 representation into an `AffineG2` point.
///
/// The first two bits of the first byte encode a flag:
/// - `COMPRESSED_INFINITY`: the point at infinity in G2.
/// - `COMPRESSED_POSITIVE` / `COMPRESSED_NEGATIVE`: choose the appropriate y‐coordinate branch.
///
/// Ref: https://github.com/succinctlabs/sp1/blob/dev/crates/verifier/src/converter.rs#L79
pub(crate) fn compressed_bytes_to_affine_g2(buf: &[u8]) -> Result<AffineG2, Error> {
    if buf.len() != 64 {
        return Err(Error::InvalidXLength);
    }

    // Extract the two-bit flag from the first byte.
    let flag = buf[0] & MASK;

    // If the flag indicates infinity, return the point at infinity in G2.
    if flag == COMPRESSED_INFINITY {
        return AffineG2::from_jacobian(G2::one()).ok_or(Error::InvalidData);
    }

    // Reconstruct x1 (imaginary part of Fq2) with flags cleared.
    let mut x1_bytes = [0u8; 32];
    x1_bytes.copy_from_slice(&buf[0..32]);
    x1_bytes[0] &= !MASK;
    let x1 = Fq::from_slice(&x1_bytes).map_err(Error::Field)?;

    // Reconstruct x0 (real part).
    let mut x0_bytes = [0u8; 32];
    x0_bytes.copy_from_slice(&buf[32..64]);
    let x0 = Fq::from_slice(&x0_bytes).map_err(Error::Field)?;

    let x_fq2 = Fq2::new(x0, x1);

    // Recover both possible y-coordinates from x.
    let (y, neg_y) = get_ys_from_x_g2(x_fq2)?;
    match flag {
        COMPRESSED_NEGATIVE => AffineG2::new(x_fq2, neg_y).map_err(Error::Group),
        COMPRESSED_POSITIVE => AffineG2::new(x_fq2, y).map_err(Error::Group),
        _ => Err(Error::InvalidData),
    }
}

/// Convert a 128-byte uncompressed G2 representation into an `AffineG2` point.
///
/// Expects the buffer to contain:
/// - bytes 0..32: x1 (imaginary part of Fq2)
/// - bytes 32..64: x0 (real part of Fq2)
/// - bytes 64..96: y1 (imaginary part of Fq2)
/// - bytes 96..128: y0 (real part of Fq2)
///
/// Ref: https://github.com/succinctlabs/sp1/blob/dev/crates/verifier/src/converter.rs#L104
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

/// Given an Fq2 element `x`, compute both possible y‐coordinates on the BN254 curve:
/// `y^2 = x^3 + b` for G2. Returns `(y, -y)`, ordered such that the first element is
/// lexicographically smaller (imaginary part first, then real part).
///
/// Ref: https://github.com/sp1-patches/bn/blob/n/v5.0.0/src/groups/mod.rs#L187
fn get_ys_from_x_g2(x: Fq2) -> Result<(Fq2, Fq2), Error> {
    // Compute y^2 = x^3 + b.
    let y_squared = (x * x * x) + G2::b();
    let y = y_squared.sqrt().ok_or(Error::InvalidPoint)?;
    let neg_y = -y;

    // Determine lexicographic ordering: compare imaginary parts, then real parts.
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
