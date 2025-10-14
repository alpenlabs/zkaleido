use std::{cmp::Ordering, fmt};

use bn::{AffineG2, Fq, Fq2, Group, G2};

use crate::{
    error::Error,
    types::constant::{
        COMPRESSED_INFINITY, COMPRESSED_NEGATIVE, COMPRESSED_POSITIVE, FQ_SIZE, G2_COMPRESSED_SIZE,
        G2_UNCOMPRESSED_SIZE, MASK,
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

impl SAffineG2 {
    /// Deserialize from GNARK-compressed bytes (64 bytes: x-coordinate (Fq2) with flag bits).
    ///
    /// Uses the GNARK compression scheme where the first two bits of the first byte encode a flag:
    /// - `COMPRESSED_INFINITY`: the point at infinity in G2.
    /// - `COMPRESSED_POSITIVE` / `COMPRESSED_NEGATIVE`: choose the appropriate y‐coordinate branch.
    pub(crate) fn from_gnark_compressed_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != G2_COMPRESSED_SIZE {
            return Err(Error::InvalidXLength);
        }

        // Extract the two-bit flag from the first byte.
        let flag = bytes[0] & MASK;

        // If the flag indicates infinity, return the point at infinity in G2.
        if flag == COMPRESSED_INFINITY {
            return Ok(SAffineG2(
                AffineG2::from_jacobian(G2::one()).ok_or(Error::InvalidData)?,
            ));
        }

        // Reconstruct x1 (imaginary part of Fq2) with flags cleared.
        let mut x1_bytes = [0u8; FQ_SIZE];
        x1_bytes.copy_from_slice(&bytes[0..FQ_SIZE]);
        x1_bytes[0] &= !MASK;
        let x1 = Fq::from_slice(&x1_bytes).map_err(Error::Field)?;

        // Reconstruct x0 (real part).
        let mut x0_bytes = [0u8; FQ_SIZE];
        x0_bytes.copy_from_slice(&bytes[FQ_SIZE..G2_COMPRESSED_SIZE]);
        let x0 = Fq::from_slice(&x0_bytes).map_err(Error::Field)?;

        let x_fq2 = Fq2::new(x0, x1);

        // Recover both possible y-coordinates from x: y^2 = x^3 + b for G2.
        let y_squared = (x_fq2 * x_fq2 * x_fq2) + G2::b();
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

        let (smaller_y, larger_y) = if is_y_less_than_neg_y {
            (y, neg_y)
        } else {
            (neg_y, y)
        };

        let selected_y = match flag {
            COMPRESSED_NEGATIVE => larger_y,
            COMPRESSED_POSITIVE => smaller_y,
            _ => return Err(Error::InvalidData),
        };

        Ok(SAffineG2(
            AffineG2::new(x_fq2, selected_y).map_err(Error::Group)?,
        ))
    }

    /// Deserialize from uncompressed bytes (128 bytes: x-coordinate + y-coordinate).
    ///
    /// Expects the buffer to contain:
    /// - bytes 0..32: x1 (imaginary part of Fq2)
    /// - bytes 32..64: x0 (real part of Fq2)
    /// - bytes 64..96: y1 (imaginary part of Fq2)
    /// - bytes 96..128: y0 (real part of Fq2)
    pub(crate) fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != G2_UNCOMPRESSED_SIZE {
            return Err(Error::InvalidXLength);
        }

        let (x_bytes, y_bytes) = bytes.split_at(G2_COMPRESSED_SIZE);
        let (x1_bytes, x0_bytes) = x_bytes.split_at(FQ_SIZE);
        let (y1_bytes, y0_bytes) = y_bytes.split_at(FQ_SIZE);

        let x1 = Fq::from_slice(x1_bytes).map_err(Error::Field)?;
        let x0 = Fq::from_slice(x0_bytes).map_err(Error::Field)?;
        let y1 = Fq::from_slice(y1_bytes).map_err(Error::Field)?;
        let y0 = Fq::from_slice(y0_bytes).map_err(Error::Field)?;

        let x = Fq2::new(x0, x1);
        let y = Fq2::new(y0, y1);

        Ok(SAffineG2(AffineG2::new(x, y).map_err(Error::Group)?))
    }

    /// Serialize to GNARK-compressed bytes (64 bytes: x-coordinate (Fq2) with flag bits).
    ///
    /// Uses the GNARK compression scheme where the first two bits of the first byte
    /// encode a flag indicating which y-coordinate to use or infinity.
    pub(crate) fn to_gnark_compressed_bytes(self) -> [u8; G2_COMPRESSED_SIZE] {
        let mut projective: G2 = self.0.into();
        projective.normalize();
        let (x, y) = (projective.x(), projective.y());

        let mut bytes = [0u8; G2_COMPRESSED_SIZE];

        // Serialize x coordinate (Fq2: imaginary part in first 32 bytes, real part in second 32
        // bytes)
        let mut x1_bytes = [0u8; FQ_SIZE];
        let mut x0_bytes = [0u8; FQ_SIZE];
        x.imaginary().to_big_endian(&mut x1_bytes).unwrap();
        x.real().to_big_endian(&mut x0_bytes).unwrap();

        // Determine which y-coordinate we have (lexicographically smaller)
        let neg_y = -y;
        let is_y_less_than_neg_y = match y
            .imaginary()
            .into_u256()
            .cmp(&neg_y.imaginary().into_u256())
        {
            Ordering::Less => true,
            Ordering::Greater => false,
            Ordering::Equal => y.real().into_u256() < neg_y.real().into_u256(),
        };

        let flag = if is_y_less_than_neg_y {
            COMPRESSED_POSITIVE
        } else {
            COMPRESSED_NEGATIVE
        };

        // Set the flag bits in the first byte of x1 (imaginary part)
        x1_bytes[0] |= flag;

        bytes[0..FQ_SIZE].copy_from_slice(&x1_bytes);
        bytes[FQ_SIZE..G2_COMPRESSED_SIZE].copy_from_slice(&x0_bytes);

        bytes
    }

    /// Serialize to uncompressed bytes (128 bytes: x-coordinate + y-coordinate, each Fq2 = 64
    /// bytes).
    pub(crate) fn to_uncompressed_bytes(self) -> [u8; G2_UNCOMPRESSED_SIZE] {
        let mut projective: G2 = self.0.into();
        projective.normalize();
        let (x, y) = (projective.x(), projective.y());

        let mut bytes = [0u8; G2_UNCOMPRESSED_SIZE];

        // Serialize x coordinate (Fq2: imaginary then real)
        x.imaginary().to_big_endian(&mut bytes[0..FQ_SIZE]).unwrap();
        x.real()
            .to_big_endian(&mut bytes[FQ_SIZE..G2_COMPRESSED_SIZE])
            .unwrap();

        // Serialize y coordinate (Fq2: imaginary then real)
        y.imaginary()
            .to_big_endian(&mut bytes[G2_COMPRESSED_SIZE..G2_COMPRESSED_SIZE + FQ_SIZE])
            .unwrap();
        y.real()
            .to_big_endian(&mut bytes[G2_COMPRESSED_SIZE + FQ_SIZE..G2_UNCOMPRESSED_SIZE])
            .unwrap();

        bytes
    }
}

impl fmt::Debug for SAffineG2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AffineG2").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use bn::{AffineG2, Group, G2};

    use crate::types::g2::SAffineG2;

    #[test]
    fn test_uncompressed_g2_roundtrip() {
        let mut rng = rand::thread_rng();
        let mut g2 = G2::random(&mut rng);
        g2.normalize();
        let g2: SAffineG2 = AffineG2::new(g2.x(), g2.y()).unwrap().into();

        let compressed_serialized_bytes = g2.to_gnark_compressed_bytes();
        let compressed_deserialized =
            SAffineG2::from_gnark_compressed_bytes(&compressed_serialized_bytes).unwrap();
        assert_eq!(g2, compressed_deserialized);

        let uncompressed_serialized_bytes = g2.to_uncompressed_bytes();
        let uncompressed_deserialized =
            SAffineG2::from_uncompressed_bytes(&uncompressed_serialized_bytes).unwrap();
        assert_eq!(g2, uncompressed_deserialized);
    }
}
