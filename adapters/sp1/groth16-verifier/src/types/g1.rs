use std::fmt;

use bn::{AffineG1, Fq, Group, G1};

use crate::{
    error::Error,
    types::constant::{COMPRESSED_NEGATIVE, COMPRESSED_POSITIVE, MASK},
};

#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) struct SAffineG1(pub AffineG1);

impl From<AffineG1> for SAffineG1 {
    fn from(value: AffineG1) -> Self {
        SAffineG1(value)
    }
}

impl From<SAffineG1> for G1 {
    fn from(value: SAffineG1) -> Self {
        value.0.into()
    }
}

impl SAffineG1 {
    /// Serialize to compressed bytes (32 bytes: x-coordinate with flag bits).
    ///
    /// The first two bits of the first byte encode a flag indicating which y-coordinate to use.
    pub(crate) fn to_compressed_bytes(self) -> [u8; 32] {
        let mut projective: G1 = self.0.into();
        projective.normalize();
        let (x, y) = (projective.x(), projective.y());

        // Serialize x coordinate to bytes
        let mut x_bytes = [0u8; 32];
        // NOTE: It is safe to unwrap because the only error is if size of slice is not of length
        // 32.
        x.to_big_endian(&mut x_bytes).unwrap();

        // Determine which y-coordinate we have (positive or negative)
        let neg_y = -y;
        let flag = if y.into_u256() < neg_y.into_u256() {
            COMPRESSED_POSITIVE
        } else {
            COMPRESSED_NEGATIVE
        };

        // Set the flag bits in the first byte
        x_bytes[0] |= flag;

        x_bytes
    }

    /// Deserialize from compressed bytes (32 bytes: x-coordinate with flag bits).
    pub(crate) fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(SAffineG1(compressed_bytes_to_affine_g1(bytes)?))
    }

    /// Serialize to uncompressed bytes (64 bytes: x-coordinate + y-coordinate).
    pub(crate) fn to_uncompressed_bytes(self) -> [u8; 64] {
        let mut projective: G1 = self.0.into();
        projective.normalize();
        let (x, y) = (projective.x(), projective.y());

        let mut bytes = [0u8; 64];
        // NOTE: It is safe to unwrap because the only error is if size of slice is not of length
        // 32.
        x.to_big_endian(&mut bytes[0..32]).unwrap();
        y.to_big_endian(&mut bytes[32..64]).unwrap();

        bytes
    }

    /// Deserialize from uncompressed bytes (64 bytes: x-coordinate + y-coordinate).
    pub(crate) fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(SAffineG1(uncompressed_bytes_to_affine_g1(bytes)?))
    }
}

impl fmt::Debug for SAffineG1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AffineG1").finish_non_exhaustive()
    }
}

/// Convert a 32-byte compressed G1 representation into an `AffineG1` point.
///
/// Interprets the first two bits (most significant) of the first byte as a flag:
/// - `COMPRESSED_POSITIVE`: use the lexicographically smaller of (y, -y) as y.
/// - `COMPRESSED_NEGATIVE`: use the lexicographically larger of (y, -y) as y.
///
/// Ref: https://github.com/succinctlabs/sp1/blob/dev/crates/verifier/src/converter.rs#L42
pub(crate) fn compressed_bytes_to_affine_g1(buf: &[u8]) -> Result<AffineG1, Error> {
    if buf.len() != 32 {
        return Err(Error::InvalidXLength);
    }

    // Extract the two-bit flag from the first byte.
    let flag = buf[0] & MASK;

    // Clear the flag bits to reconstruct the x-coordinate bytes.
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(buf);
    x_bytes[0] &= !MASK;

    // Parse the x-coordinate as an Fq element.
    let x_fq = Fq::from_slice(&x_bytes).map_err(|_| Error::InvalidPoint)?;

    // Recover both possible y-coordinates from x.
    let (y, neg_y) = get_ys_from_x_g1(x_fq)?;
    match flag {
        COMPRESSED_NEGATIVE => AffineG1::new(x_fq, neg_y).map_err(Error::Group),
        COMPRESSED_POSITIVE => AffineG1::new(x_fq, y).map_err(Error::Group),
        _ => Err(Error::InvalidData),
    }
}

/// Convert a 64-byte uncompressed G1 representation into an `AffineG1` point.
///
/// Expects the buffer to contain the big‐endian x-coordinate in bytes 0..32,
/// followed by the big‐endian y-coordinate in bytes 32..64.
///
/// Ref: https://github.com/succinctlabs/sp1/blob/dev/crates/verifier/src/converter.rs#L61
pub(crate) fn uncompressed_bytes_to_affine_g1(buf: &[u8]) -> Result<AffineG1, Error> {
    if buf.len() != 64 {
        return Err(Error::InvalidXLength);
    }

    let (x_bytes, y_bytes) = buf.split_at(32);
    let x = Fq::from_slice(x_bytes).map_err(Error::Field)?;
    let y = Fq::from_slice(y_bytes).map_err(Error::Field)?;

    AffineG1::new(x, y).map_err(Error::Group)
}

/// Given an Fq element `x`, compute both possible y‐coordinates on the BN254 curve:
/// `y^2 = x^3 + b` for G1. Returns `(y, -y)`, ordered such that the first element is
/// numerically smaller.
///
/// Ref: https://github.com/sp1-patches/bn/blob/n/v5.0.0/src/groups/mod.rs#L187
fn get_ys_from_x_g1(x: Fq) -> Result<(Fq, Fq), Error> {
    // Compute y^2 = x^3 + b.
    let y_squared = (x * x * x) + G1::b();
    let y = y_squared.sqrt().ok_or(Error::InvalidPoint)?;
    let neg_y = -y;

    // Compare as 256‐bit integers.
    if y.into_u256() < neg_y.into_u256() {
        Ok((y, neg_y))
    } else {
        Ok((neg_y, y))
    }
}
