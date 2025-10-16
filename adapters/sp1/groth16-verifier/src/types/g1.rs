use std::fmt;

use bn::{AffineG1, Fq, Group, G1};

use crate::{
    error::{BufferLengthError, InvalidDataFormatError, InvalidPointError, SerializationError},
    types::constant::{
        COMPRESSED_NEGATIVE, COMPRESSED_POSITIVE, FQ_SIZE, G1_COMPRESSED_SIZE,
        G1_UNCOMPRESSED_SIZE, MASK,
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

impl SAffineG1 {
    /// Deserialize from GNARK-compressed bytes (32 bytes: x-coordinate with flag bits).
    ///
    /// Uses the GNARK compression scheme where the first two bits (most significant) of
    /// the first byte encode a flag:
    /// - `COMPRESSED_POSITIVE`: use the lexicographically smaller of (y, -y) as y.
    /// - `COMPRESSED_NEGATIVE`: use the lexicographically larger of (y, -y) as y.
    pub(crate) fn from_gnark_compressed_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != G1_COMPRESSED_SIZE {
            return Err(BufferLengthError {
                context: "Gnark-compressed G1 point",
                expected: G1_COMPRESSED_SIZE,
                actual: bytes.len(),
            }
            .into());
        }

        // Extract the two-bit flag from the first byte.
        let flag = bytes[0] & MASK;

        // Clear the flag bits to reconstruct the x-coordinate bytes.
        let mut x_bytes = [0u8; FQ_SIZE];
        x_bytes.copy_from_slice(bytes);
        x_bytes[0] &= !MASK;

        // Parse the x-coordinate as an Fq element.
        let x_fq = Fq::from_slice(&x_bytes)?;

        // Recover both possible y-coordinates from x: y^2 = x^3 + b for G1.
        let y_squared = (x_fq * x_fq * x_fq) + G1::b();
        let y = y_squared.sqrt().ok_or(InvalidPointError)?;
        let neg_y = -y;

        // Compare as 256‐bit integers to find smaller one.
        let (smaller_y, larger_y) = if y.into_u256() < neg_y.into_u256() {
            (y, neg_y)
        } else {
            (neg_y, y)
        };

        let selected_y = match flag {
            COMPRESSED_NEGATIVE => larger_y,
            COMPRESSED_POSITIVE => smaller_y,
            _ => return Err(InvalidDataFormatError.into()),
        };

        Ok(SAffineG1(AffineG1::new(x_fq, selected_y)?))
    }

    /// Deserialize from uncompressed bytes (64 bytes: x-coordinate + y-coordinate).
    ///
    /// Expects the buffer to contain the big‐endian x-coordinate in bytes 0..32,
    /// followed by the big‐endian y-coordinate in bytes 32..64.
    pub(crate) fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() != G1_UNCOMPRESSED_SIZE {
            return Err(BufferLengthError {
                context: "Uncompressed G1 point",
                expected: G1_UNCOMPRESSED_SIZE,
                actual: bytes.len(),
            }
            .into());
        }

        let (x_bytes, y_bytes) = bytes.split_at(FQ_SIZE);
        let x = Fq::from_slice(x_bytes)?;
        let y = Fq::from_slice(y_bytes)?;

        Ok(SAffineG1(AffineG1::new(x, y)?))
    }

    /// Serialize to GNARK-compressed bytes (32 bytes: x-coordinate with flag bits).
    ///
    /// Uses the GNARK compression scheme where the first two bits of the first byte
    /// encode a flag indicating which y-coordinate to use.
    pub(crate) fn to_gnark_compressed_bytes(self) -> [u8; G1_COMPRESSED_SIZE] {
        let mut projective: G1 = self.0.into();
        projective.normalize();
        let (x, y) = (projective.x(), projective.y());

        // Serialize x coordinate to bytes
        let mut x_bytes = [0u8; G1_COMPRESSED_SIZE];
        // NOTE: It is safe to unwrap because the only error is if size of slice is not of length
        // FQ_SIZE.
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

    /// Serialize to uncompressed bytes (64 bytes: x-coordinate + y-coordinate).
    pub(crate) fn to_uncompressed_bytes(self) -> [u8; G1_UNCOMPRESSED_SIZE] {
        let mut projective: G1 = self.0.into();
        projective.normalize();
        let (x, y) = (projective.x(), projective.y());

        let mut bytes = [0u8; G1_UNCOMPRESSED_SIZE];
        // NOTE: It is safe to unwrap because the only error is if size of slice is not of length
        // FQ_SIZE.
        x.to_big_endian(&mut bytes[0..FQ_SIZE]).unwrap();
        y.to_big_endian(&mut bytes[FQ_SIZE..G1_UNCOMPRESSED_SIZE])
            .unwrap();

        bytes
    }
}

impl fmt::Debug for SAffineG1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AffineG1").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use bn::{AffineG1, Group, G1};

    use crate::types::g1::SAffineG1;

    #[test]
    fn test_uncompressed_g1_roundtrip() {
        let mut rng = rand::thread_rng();
        let mut g1 = G1::random(&mut rng);
        g1.normalize();
        let g1: SAffineG1 = AffineG1::new(g1.x(), g1.y()).unwrap().into();

        let compressed_serialized_bytes = g1.to_gnark_compressed_bytes();
        let compressed_deserialized =
            SAffineG1::from_gnark_compressed_bytes(&compressed_serialized_bytes).unwrap();
        assert_eq!(g1, compressed_deserialized);

        let uncompressed_serialized_bytes = g1.to_uncompressed_bytes();
        let uncompressed_deserialized =
            SAffineG1::from_uncompressed_bytes(&uncompressed_serialized_bytes).unwrap();
        assert_eq!(g1, uncompressed_deserialized);
    }
}
