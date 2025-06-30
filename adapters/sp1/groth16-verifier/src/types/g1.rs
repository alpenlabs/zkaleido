use std::fmt;

use bn::{AffineG1, Fq, Group, G1};
use serde::{Deserialize, Serialize, Serializer};

use crate::{
    error::Error,
    types::{
        constant::{COMPRESSED_NEGATIVE, COMPRESSED_POSITIVE, MASK},
        utils::{bytes_to_hex, hex_to_bytes},
    },
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

#[derive(Serialize, Deserialize)]
struct SAffineG1Helper {
    x: String,
    y: String,
}

impl From<&SAffineG1> for SAffineG1Helper {
    fn from(value: &SAffineG1) -> Self {
        // Convert to projective to access coordinates
        let mut projective: G1 = (value.0).into();
        projective.normalize();
        let (x, y) = (projective.x(), projective.y());

        SAffineG1Helper {
            x: serialize_fq_to_hex(&x),
            y: serialize_fq_to_hex(&y),
        }
    }
}

impl TryFrom<SAffineG1Helper> for SAffineG1 {
    type Error = Error;
    fn try_from(value: SAffineG1Helper) -> Result<Self, Self::Error> {
        let x = deserialize_fq_from_hex(&value.x)?;
        let y = deserialize_fq_from_hex(&value.y)?;
        let z = Fq::one();

        let projective = G1::new(x, y, z);

        let g1 = AffineG1::from_jacobian(projective).ok_or(Error::InvalidPoint)?;
        Ok(SAffineG1(g1))
    }
}

impl Serialize for SAffineG1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SAffineG1Helper::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SAffineG1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = SAffineG1Helper::deserialize(deserializer)?;
        SAffineG1::try_from(helper).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for SAffineG1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let helper = SAffineG1Helper::from(self);
        f.debug_struct("AffineG1")
            .field("x", &helper.x)
            .field("y", &helper.y)
            .finish()
    }
}

// Helper functions for Fq serialization
pub(super) fn serialize_fq_to_hex(fq: &Fq) -> String {
    let mut slice = [0u8; 32];
    // NOTE: It is safe to unwrap because the only error is if size of slice is not of length 32.
    fq.to_big_endian(&mut slice).unwrap();
    bytes_to_hex(&slice)
}

pub(super) fn deserialize_fq_from_hex(hex_str: &str) -> Result<Fq, Error> {
    let bytes = hex_to_bytes(hex_str)?;
    Fq::from_slice(&bytes).map_err(|_| Error::FailedToGetFrFromRandomBytes)
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
