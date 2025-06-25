use std::{cmp::Ordering, fmt};

use bn::{AffineG2, Fq, Fq2, Group, G2};
use serde::{Deserialize, Serialize, Serializer};

use crate::{
    error::Error,
    types::{
        constant::{COMPRESSED_INFINITY, COMPRESSED_NEGATIVE, COMPRESSED_POSITIVE, MASK},
        g1::{deserialize_fq_from_hex, serialize_fq_to_hex},
    },
};

#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) struct SAffineG2(pub AffineG2);

impl From<AffineG2> for SAffineG2 {
    fn from(value: AffineG2) -> Self {
        SAffineG2(value)
    }
}

impl From<SAffineG2> for G2 {
    fn from(value: SAffineG2) -> Self {
        value.0.into()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SAffineG2Helper {
    x: Fq2Helper,
    y: Fq2Helper,
}

#[derive(Serialize, Deserialize)]
struct Fq2Helper {
    real: String,
    imaginary: String,
}

impl From<&SAffineG2> for SAffineG2Helper {
    fn from(value: &SAffineG2) -> Self {
        let mut projective: G2 = (value.0).into();
        projective.normalize();
        let (x, y) = (projective.x(), projective.y());

        SAffineG2Helper {
            x: serialize_fq2_to_hex(&x),
            y: serialize_fq2_to_hex(&y),
        }
    }
}

impl TryFrom<SAffineG2Helper> for SAffineG2 {
    type Error = Error;
    fn try_from(value: SAffineG2Helper) -> Result<Self, Self::Error> {
        let x = deserialize_fq2_from_hex(&value.x)?;
        let y = deserialize_fq2_from_hex(&value.y)?;
        let z = Fq2::one();

        let projective = G2::new(x, y, z);

        let g2 = AffineG2::from_jacobian(projective).ok_or(Error::InvalidPoint)?;
        Ok(SAffineG2(g2))
    }
}

impl Serialize for SAffineG2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SAffineG2Helper::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SAffineG2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = SAffineG2Helper::deserialize(deserializer)?;
        SAffineG2::try_from(helper).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for Fq2Helper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fq2")
            .field("x", &self.real)
            .field("y", &self.imaginary)
            .finish()
    }
}

impl fmt::Debug for SAffineG2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let helper = SAffineG2Helper::from(self);
        f.debug_struct("AffineG2")
            .field("x", &helper.x)
            .field("y", &helper.y)
            .finish()
    }
}

fn serialize_fq2_to_hex(fq2: &Fq2) -> Fq2Helper {
    let real = fq2.real();
    let imaginary = fq2.imaginary();

    let real = serialize_fq_to_hex(&real);
    let imaginary = serialize_fq_to_hex(&imaginary);

    Fq2Helper { real, imaginary }
}

fn deserialize_fq2_from_hex(hex: &Fq2Helper) -> Result<Fq2, Error> {
    let real = deserialize_fq_from_hex(&hex.real)?;
    let imaginary = deserialize_fq_from_hex(&hex.imaginary)?;
    Ok(Fq2::new(real, imaginary))
}

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
pub(crate) fn uncompressed_bytes_to_affine_g2(buf: &[u8]) -> Result<AffineG2, Error> {
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

    // REVIEW: This avoids the subcheck group by assuming X and Y are valid, reducing cycle counts.
    // If they are invalid the proof verification fails
    let g2 = G2::new(x, y, Fq2::one());
    AffineG2::from_jacobian(g2).ok_or(Error::InvalidPoint)
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
