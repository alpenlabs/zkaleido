use bn::{AffineG2, G2};

use crate::{
    error::{BufferLengthError, Groth16Error, InvalidPointError},
    types::{
        constant::{
            G1_COMPRESSED_SIZE, G1_UNCOMPRESSED_SIZE, G2_COMPRESSED_SIZE, G2_UNCOMPRESSED_SIZE,
            GNARK_VK_COMPRESSED_G2_BETA_OFFSET, GNARK_VK_COMPRESSED_G2_DELTA_OFFSET,
            GNARK_VK_COMPRESSED_G2_GAMMA_OFFSET, GNARK_VK_COMPRESSED_HEADER_SIZE,
            GNARK_VK_COMPRESSED_NUM_K_OFFSET, GROTH16_VK_UNCOMPRESSED_HEADER_SIZE, U32_SIZE,
        },
        g1::SAffineG1,
        g2::SAffineG2,
    },
};

/// G1 elements of the verification key.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Groth16G1 {
    pub(crate) alpha: SAffineG1,
    pub(crate) k: Vec<SAffineG1>,
}

/// G2 elements of the verification key.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Groth16G2 {
    pub(crate) beta: SAffineG2,
    pub(crate) delta: SAffineG2,
    pub(crate) gamma: SAffineG2,
}

/// Verification key for the Groth16 proof.
#[derive(Clone, Debug, PartialEq)]
pub struct Groth16VerifyingKey {
    pub(crate) g1: Groth16G1,
    pub(crate) g2: Groth16G2,
}

impl Groth16VerifyingKey {
    /// Load a Groth16 verifying key from a GNARK-style compressed byte slice.
    ///
    /// Byte layout (following GNARK's BN254 VerifyingKey serialization format):
    /// - [0..32)      : G1 α (compressed)
    /// - [32..64)     : G1 β (unused, Bellman-compatibility padding)
    /// - [64..128)    : G2 β (compressed)
    /// - [128..192)   : G2 γ (compressed)
    /// - [192..224)   : G1 δ (unused, Bellman-compatibility padding)
    /// - [224..288)   : G2 δ (compressed)
    /// - [288..292)   : `num_k` (u32 BE)
    /// - [292..292+i) : `i = 32 * num_k` bytes of G1 K-points (compressed)
    ///
    /// Reference: <https://pkg.go.dev/github.com/consensys/gnark/backend/groth16/bn254#VerifyingKey>
    pub fn from_gnark_bytes(buffer: &[u8]) -> Result<Self, Groth16Error> {
        // Validate minimum buffer length for the "header" (all fixed-size fields before K points).
        // The header includes: alpha, beta, gamma, delta (with GNARK padding), and num_k field.
        // The actual VK size depends on num_k, which we read from the header.
        if buffer.len() < GNARK_VK_COMPRESSED_HEADER_SIZE {
            return Err(Groth16Error::Serialization(
                BufferLengthError {
                    context: "Compressed Gnark Groth16 VK header",
                    expected: GNARK_VK_COMPRESSED_HEADER_SIZE,
                    actual: buffer.len(),
                }
                .into(),
            ));
        }

        // Read the number of K points (u32, big‐endian).
        let num_k = u32::from_be_bytes([
            buffer[GNARK_VK_COMPRESSED_NUM_K_OFFSET],
            buffer[GNARK_VK_COMPRESSED_NUM_K_OFFSET + 1],
            buffer[GNARK_VK_COMPRESSED_NUM_K_OFFSET + 2],
            buffer[GNARK_VK_COMPRESSED_NUM_K_OFFSET + 3],
        ]);

        // Validate that buffer has enough bytes for all K points
        let expected_size = GNARK_VK_COMPRESSED_HEADER_SIZE + (num_k as usize * G1_COMPRESSED_SIZE);
        if buffer.len() < expected_size {
            return Err(Groth16Error::Serialization(
                BufferLengthError {
                    context: "Compressed Gnark Groth16 VK",
                    expected: expected_size,
                    actual: buffer.len(),
                }
                .into(),
            ));
        }

        // Parse G1 alpha (GNARK-compressed).
        let g1_alpha = SAffineG1::from_gnark_compressed_bytes(&buffer[..G1_COMPRESSED_SIZE])?;

        // Parse G2 beta, gamma, delta (GNARK-compressed).
        let g2_beta = SAffineG2::from_gnark_compressed_bytes(
            &buffer[GNARK_VK_COMPRESSED_G2_BETA_OFFSET
                ..GNARK_VK_COMPRESSED_G2_BETA_OFFSET + G2_COMPRESSED_SIZE],
        )?;
        let g2_gamma = SAffineG2::from_gnark_compressed_bytes(
            &buffer[GNARK_VK_COMPRESSED_G2_GAMMA_OFFSET
                ..GNARK_VK_COMPRESSED_G2_GAMMA_OFFSET + G2_COMPRESSED_SIZE],
        )?;
        let g2_delta = SAffineG2::from_gnark_compressed_bytes(
            &buffer[GNARK_VK_COMPRESSED_G2_DELTA_OFFSET
                ..GNARK_VK_COMPRESSED_G2_DELTA_OFFSET + G2_COMPRESSED_SIZE],
        )?;

        // Negate beta for the verifier's purpose.
        let neg_g2_beta = SAffineG2(
            AffineG2::from_jacobian(-G2::from(g2_beta.0))
                .ok_or(InvalidPointError)
                .map_err(|e| Groth16Error::Serialization(e.into()))?,
        );

        let mut k = Vec::with_capacity(num_k as usize);
        let mut offset = GNARK_VK_COMPRESSED_HEADER_SIZE;
        for _ in 0..num_k {
            let point = SAffineG1::from_gnark_compressed_bytes(
                &buffer[offset..offset + G1_COMPRESSED_SIZE],
            )?;
            k.push(point);
            offset += G1_COMPRESSED_SIZE;
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

    /// Deserialize from uncompressed bytes.
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, Groth16Error> {
        if bytes.len() < GROTH16_VK_UNCOMPRESSED_HEADER_SIZE {
            return Err(Groth16Error::Serialization(
                BufferLengthError {
                    context: "Uncompressed Groth16 VK Header",
                    expected: GROTH16_VK_UNCOMPRESSED_HEADER_SIZE,
                    actual: bytes.len(),
                }
                .into(),
            ));
        }

        // Read the number of K points (u32, big‐endian).
        let num_k_offset = G1_UNCOMPRESSED_SIZE + 3 * G2_UNCOMPRESSED_SIZE;
        let num_k = u32::from_be_bytes([
            bytes[num_k_offset],
            bytes[num_k_offset + 1],
            bytes[num_k_offset + 2],
            bytes[num_k_offset + 3],
        ]);

        // Validate buffer size
        let expected_size =
            GROTH16_VK_UNCOMPRESSED_HEADER_SIZE + (num_k as usize * G1_UNCOMPRESSED_SIZE);
        if bytes.len() != expected_size {
            return Err(Groth16Error::Serialization(
                BufferLengthError {
                    context: "Uncompressed Groth16 VK",
                    expected: expected_size,
                    actual: bytes.len(),
                }
                .into(),
            ));
        }

        // Parse G1 alpha (uncompressed).
        let g1_alpha = SAffineG1::from_uncompressed_bytes(&bytes[0..G1_UNCOMPRESSED_SIZE])?;

        // Parse G2 beta, gamma, delta (uncompressed).
        let g2_beta_point = SAffineG2::from_uncompressed_bytes(
            &bytes[G1_UNCOMPRESSED_SIZE..G1_UNCOMPRESSED_SIZE + G2_UNCOMPRESSED_SIZE],
        )?;
        let g2_gamma = SAffineG2::from_uncompressed_bytes(
            &bytes[G1_UNCOMPRESSED_SIZE + G2_UNCOMPRESSED_SIZE
                ..G1_UNCOMPRESSED_SIZE + 2 * G2_UNCOMPRESSED_SIZE],
        )?;
        let g2_delta = SAffineG2::from_uncompressed_bytes(
            &bytes[G1_UNCOMPRESSED_SIZE + 2 * G2_UNCOMPRESSED_SIZE
                ..G1_UNCOMPRESSED_SIZE + 3 * G2_UNCOMPRESSED_SIZE],
        )?;

        // Negate beta for the verifier's purpose.
        let neg_g2_beta = SAffineG2(
            AffineG2::from_jacobian(-G2::from(g2_beta_point.0))
                .ok_or(InvalidPointError)
                .map_err(|e| Groth16Error::Serialization(e.into()))?,
        );

        let mut k = Vec::with_capacity(num_k as usize);
        let mut offset = GROTH16_VK_UNCOMPRESSED_HEADER_SIZE;
        for _ in 0..num_k {
            let point =
                SAffineG1::from_uncompressed_bytes(&bytes[offset..offset + G1_UNCOMPRESSED_SIZE])?;
            k.push(point);
            offset += G1_UNCOMPRESSED_SIZE;
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

    /// Serialize to GNARK bytes (with Bellman-compatibility padding).
    ///
    /// Uses the GNARK compression scheme with padding for unused G1 fields.
    ///
    /// Layout (same as `from_gnark_bytes`):
    /// - bytes 0..32:     G1 α (GNARK-compressed)
    /// - bytes 32..64:    G1 β (unused, Bellman-compatibility padding - zeroed)
    /// - bytes 64..128:   G2 β (GNARK-compressed)
    /// - bytes 128..192:  G2 γ (GNARK-compressed)
    /// - bytes 192..224:  G1 δ (unused, Bellman-compatibility padding - zeroed)
    /// - bytes 224..288:  G2 δ (GNARK-compressed)
    /// - bytes 288..292:  `num_k` (u32 BE)
    /// - bytes 292..:     `32 * num_k` bytes of G1 K-points (GNARK-compressed)
    pub fn to_gnark_bytes(&self) -> Vec<u8> {
        let num_k = self.g1.k.len() as u32;
        let total_size = GNARK_VK_COMPRESSED_HEADER_SIZE + (num_k as usize * G1_COMPRESSED_SIZE);
        let mut bytes = vec![0u8; total_size];

        // Serialize G1 alpha (GNARK-compressed)
        bytes[0..G1_COMPRESSED_SIZE].copy_from_slice(&self.g1.alpha.to_gnark_compressed_bytes());

        // Padding from 32..64 is automatically zero

        // Serialize G2 beta (GNARK-compressed) - need to negate it back
        // Note: GNARK stores beta, but we store -beta internally
        let beta_affine = AffineG2::from_jacobian(-G2::from(self.g2.beta.0)).unwrap();
        let beta_point = SAffineG2(beta_affine);
        bytes[GNARK_VK_COMPRESSED_G2_BETA_OFFSET
            ..GNARK_VK_COMPRESSED_G2_BETA_OFFSET + G2_COMPRESSED_SIZE]
            .copy_from_slice(&beta_point.to_gnark_compressed_bytes());

        // Serialize G2 gamma (GNARK-compressed)
        bytes[GNARK_VK_COMPRESSED_G2_GAMMA_OFFSET
            ..GNARK_VK_COMPRESSED_G2_GAMMA_OFFSET + G2_COMPRESSED_SIZE]
            .copy_from_slice(&self.g2.gamma.to_gnark_compressed_bytes());

        // Padding from 192..224 is automatically zero

        // Serialize G2 delta (GNARK-compressed)
        bytes[GNARK_VK_COMPRESSED_G2_DELTA_OFFSET
            ..GNARK_VK_COMPRESSED_G2_DELTA_OFFSET + G2_COMPRESSED_SIZE]
            .copy_from_slice(&self.g2.delta.to_gnark_compressed_bytes());

        // Serialize num_k
        bytes[GNARK_VK_COMPRESSED_NUM_K_OFFSET..GNARK_VK_COMPRESSED_NUM_K_OFFSET + U32_SIZE]
            .copy_from_slice(&num_k.to_be_bytes());

        // Serialize K points
        let mut offset = GNARK_VK_COMPRESSED_HEADER_SIZE;
        for k_point in &self.g1.k {
            bytes[offset..offset + G1_COMPRESSED_SIZE]
                .copy_from_slice(&k_point.to_gnark_compressed_bytes());
            offset += G1_COMPRESSED_SIZE;
        }

        bytes
    }

    /// Serialize to uncompressed bytes.
    ///
    /// Layout:
    /// - bytes 0..64:      G1 α (uncompressed)
    /// - bytes 64..192:    G2 β (uncompressed)
    /// - bytes 192..320:   G2 γ (uncompressed)
    /// - bytes 320..448:   G2 δ (uncompressed)
    /// - bytes 448..452:   `num_k` (u32 BE)
    /// - bytes 452..:      `64 * num_k` bytes of G1 K-points (uncompressed)
    pub fn to_uncompressed_bytes(&self) -> Vec<u8> {
        let num_k = self.g1.k.len() as u32;
        let total_size =
            GROTH16_VK_UNCOMPRESSED_HEADER_SIZE + (num_k as usize * G1_UNCOMPRESSED_SIZE);
        let mut bytes = vec![0u8; total_size];

        // Serialize G1 alpha (uncompressed)
        bytes[0..G1_UNCOMPRESSED_SIZE].copy_from_slice(&self.g1.alpha.to_uncompressed_bytes());

        // Serialize G2 beta (uncompressed) - need to negate it back
        let beta_affine = AffineG2::from_jacobian(-G2::from(self.g2.beta.0)).unwrap();
        let beta_point = SAffineG2(beta_affine);
        bytes[G1_UNCOMPRESSED_SIZE..G1_UNCOMPRESSED_SIZE + G2_UNCOMPRESSED_SIZE]
            .copy_from_slice(&beta_point.to_uncompressed_bytes());

        // Serialize G2 gamma (uncompressed)
        bytes[G1_UNCOMPRESSED_SIZE + G2_UNCOMPRESSED_SIZE
            ..G1_UNCOMPRESSED_SIZE + 2 * G2_UNCOMPRESSED_SIZE]
            .copy_from_slice(&self.g2.gamma.to_uncompressed_bytes());

        // Serialize G2 delta (uncompressed)
        bytes[G1_UNCOMPRESSED_SIZE + 2 * G2_UNCOMPRESSED_SIZE
            ..G1_UNCOMPRESSED_SIZE + 3 * G2_UNCOMPRESSED_SIZE]
            .copy_from_slice(&self.g2.delta.to_uncompressed_bytes());

        // Serialize num_k
        bytes[G1_UNCOMPRESSED_SIZE + 3 * G2_UNCOMPRESSED_SIZE
            ..G1_UNCOMPRESSED_SIZE + 3 * G2_UNCOMPRESSED_SIZE + U32_SIZE]
            .copy_from_slice(&num_k.to_be_bytes());

        // Serialize K points
        let mut offset = GROTH16_VK_UNCOMPRESSED_HEADER_SIZE;
        for k_point in &self.g1.k {
            bytes[offset..offset + G1_UNCOMPRESSED_SIZE]
                .copy_from_slice(&k_point.to_uncompressed_bytes());
            offset += G1_UNCOMPRESSED_SIZE;
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use sp1_verifier::GROTH16_VK_BYTES;

    use super::*;
    use crate::{SP1_GROTH16_VK_COMPRESSED_SIZE, SP1_GROTH16_VK_UNCOMPRESSED_SIZE};

    #[test]
    fn test_vk_gnark_roundtrip() {
        let vk = Groth16VerifyingKey::from_gnark_bytes(&GROTH16_VK_BYTES).unwrap();

        // Serialize to GNARK format and deserialize
        let gnark_bytes = vk.to_gnark_bytes();
        assert_eq!(gnark_bytes.len(), SP1_GROTH16_VK_COMPRESSED_SIZE);
        let deserialized = Groth16VerifyingKey::from_gnark_bytes(&gnark_bytes).unwrap();

        assert_eq!(vk, deserialized);
    }

    #[test]
    fn test_vk_uncompressed_roundtrip() {
        let vk = Groth16VerifyingKey::from_gnark_bytes(&GROTH16_VK_BYTES).unwrap();

        // Convert to uncompressed and back
        let uncompressed = vk.to_uncompressed_bytes();
        assert_eq!(uncompressed.len(), SP1_GROTH16_VK_UNCOMPRESSED_SIZE);
        let recovered = Groth16VerifyingKey::from_uncompressed_bytes(&uncompressed).unwrap();

        assert_eq!(vk, recovered);
    }

    #[test]
    fn test_vk_from_gnark_bytes_invalid_size() {
        // Test with buffer that's too small (less than minimum required)
        let small_buffer = vec![0u8; 100];
        let result = Groth16VerifyingKey::from_gnark_bytes(&small_buffer);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Groth16Error::Serialization(_)
        ));

        // Test with buffer that has valid header but not enough K points
        let mut partial_buffer = vec![0u8; GNARK_VK_COMPRESSED_HEADER_SIZE + 4];
        // Set num_k to 2, but only provide 4 bytes (not enough for even 1 G1 point which needs 32)
        partial_buffer[GNARK_VK_COMPRESSED_NUM_K_OFFSET..GNARK_VK_COMPRESSED_NUM_K_OFFSET + 4]
            .copy_from_slice(&2u32.to_be_bytes());
        let result = Groth16VerifyingKey::from_gnark_bytes(&partial_buffer);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Groth16Error::Serialization(_)
        ));
    }
}
