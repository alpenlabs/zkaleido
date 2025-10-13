use bn::{AffineG2, G2};

use crate::{
    error::{Error, Groth16Error},
    types::{
        g1::{compressed_bytes_to_affine_g1, SAffineG1},
        g2::{compressed_bytes_to_affine_g2, SAffineG2},
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
    /// Byte layout (same as for `SP1Groth16Verifier::load`):
    /// - [0..32)      : G1 α (compressed)
    /// - [64..128)    : G2 β
    /// - [128..192)   : G2 γ (compressed)
    /// - [224..288)   : G2 δ (compressed)
    /// - [288..292)   : `num_k` (u32 BE)
    /// - [292..292+i) : `i = 32 * num_k` bytes of G1 K-points
    ///
    /// Note: slicing beyond `buffer.len()` will panic. Validate length before calling if you
    /// need to gracefully handle malformed input.
    pub fn load_from_gnark_bytes(buffer: &[u8]) -> Result<Self, Groth16Error> {
        // Parse G1 alpha (compressed).
        let g1_alpha = SAffineG1(compressed_bytes_to_affine_g1(&buffer[..32])?);

        // Parse G2 beta, gamma, delta (compressed).
        let g2_beta = compressed_bytes_to_affine_g2(&buffer[64..128])?;
        let g2_gamma = SAffineG2(compressed_bytes_to_affine_g2(&buffer[128..192])?);
        let g2_delta = SAffineG2(compressed_bytes_to_affine_g2(&buffer[224..288])?);

        // Negate beta for the verifier’s purpose.
        let neg_g2_beta =
            SAffineG2(AffineG2::from_jacobian(-G2::from(g2_beta)).ok_or(Error::InvalidPoint)?);

        // Read the number of K points (u32, big‐endian).
        let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
        let mut k = Vec::with_capacity(num_k as usize);
        let mut offset = 292;
        for _ in 0..num_k {
            let point = SAffineG1(compressed_bytes_to_affine_g1(&buffer[offset..offset + 32])?);
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

    /// Serialize to compressed bytes.
    ///
    /// Layout:
    /// - bytes 0..32:     G1 α (compressed)
    /// - bytes 32..96:    G2 β (compressed)
    /// - bytes 96..160:   G2 γ (compressed)
    /// - bytes 160..224:  G2 δ (compressed)
    /// - bytes 224..228:  `num_k` (u32 BE)
    /// - bytes 228..:     `32 * num_k` bytes of G1 K-points (compressed)
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        let num_k = self.g1.k.len() as u32;
        let total_size = 228 + (num_k as usize * 32);
        let mut bytes = vec![0u8; total_size];

        // Serialize G1 alpha (compressed)
        bytes[0..32].copy_from_slice(&self.g1.alpha.to_compressed_bytes());

        // Serialize G2 beta (compressed) - need to negate it back
        // Note: GNARK stores beta, but we store -beta internally
        let beta_affine = AffineG2::from_jacobian(-G2::from(self.g2.beta.0)).unwrap();
        let beta_point = SAffineG2(beta_affine);
        bytes[32..96].copy_from_slice(&beta_point.to_compressed_bytes());

        // Serialize G2 gamma (compressed)
        bytes[96..160].copy_from_slice(&self.g2.gamma.to_compressed_bytes());

        // Serialize G2 delta (compressed)
        bytes[160..224].copy_from_slice(&self.g2.delta.to_compressed_bytes());

        // Serialize num_k
        bytes[224..228].copy_from_slice(&num_k.to_be_bytes());

        // Serialize K points
        let mut offset = 228;
        for k_point in &self.g1.k {
            bytes[offset..offset + 32].copy_from_slice(&k_point.to_compressed_bytes());
            offset += 32;
        }

        bytes
    }

    /// Deserialize from compressed bytes.
    ///
    /// This is an alias for [`load_from_gnark_bytes`](Self::load_from_gnark_bytes) but accepts
    /// the compact format (without padding).
    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, Groth16Error> {
        if bytes.len() < 228 {
            return Err(Groth16Error::GeneralError(Error::InvalidData));
        }

        // Parse G1 alpha (compressed).
        let g1_alpha = SAffineG1::from_compressed_bytes(&bytes[0..32])?;

        // Parse G2 beta, gamma, delta (compressed).
        let g2_beta_point = SAffineG2::from_compressed_bytes(&bytes[32..96])?;
        let g2_gamma = SAffineG2::from_compressed_bytes(&bytes[96..160])?;
        let g2_delta = SAffineG2::from_compressed_bytes(&bytes[160..224])?;

        // Negate beta for the verifier's purpose.
        let neg_g2_beta = SAffineG2(
            AffineG2::from_jacobian(-G2::from(g2_beta_point.0)).ok_or(Error::InvalidPoint)?,
        );

        // Read the number of K points (u32, big‐endian).
        let num_k = u32::from_be_bytes([bytes[224], bytes[225], bytes[226], bytes[227]]);

        // Validate buffer size
        let expected_size = 228 + (num_k as usize * 32);
        if bytes.len() != expected_size {
            return Err(Groth16Error::GeneralError(Error::InvalidData));
        }

        let mut k = Vec::with_capacity(num_k as usize);
        let mut offset = 228;
        for _ in 0..num_k {
            let point = SAffineG1::from_compressed_bytes(&bytes[offset..offset + 32])?;
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

    /// Serialize to uncompressed bytes.
    ///
    /// Layout (with GNARK padding):
    /// - bytes 0..64:      G1 α (uncompressed)
    /// - bytes 64..192:    G2 β (uncompressed)
    /// - bytes 192..256:   G2 γ (uncompressed)
    /// - bytes 256..384:   G2 δ (uncompressed)
    /// - bytes 384..388:   `num_k` (u32 BE)
    /// - bytes 388..:      `64 * num_k` bytes of G1 K-points (uncompressed)
    pub fn to_uncompressed_bytes(&self) -> Vec<u8> {
        let num_k = self.g1.k.len() as u32;
        let total_size = 388 + (num_k as usize * 64);
        let mut bytes = vec![0u8; total_size];

        // Serialize G1 alpha (uncompressed)
        bytes[0..64].copy_from_slice(&self.g1.alpha.to_uncompressed_bytes());

        // Serialize G2 beta (uncompressed) - need to negate it back
        let beta_affine = AffineG2::from_jacobian(-G2::from(self.g2.beta.0)).unwrap();
        let beta_point = SAffineG2(beta_affine);
        bytes[64..192].copy_from_slice(&beta_point.to_uncompressed_bytes());

        // Serialize G2 gamma (uncompressed)
        bytes[192..256].copy_from_slice(&self.g2.gamma.to_uncompressed_bytes());

        // Serialize G2 delta (uncompressed)
        bytes[256..384].copy_from_slice(&self.g2.delta.to_uncompressed_bytes());

        // Serialize num_k
        bytes[384..388].copy_from_slice(&num_k.to_be_bytes());

        // Serialize K points
        let mut offset = 388;
        for k_point in &self.g1.k {
            bytes[offset..offset + 64].copy_from_slice(&k_point.to_uncompressed_bytes());
            offset += 64;
        }

        bytes
    }

    /// Deserialize from uncompressed bytes.
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, Groth16Error> {
        if bytes.len() < 388 {
            return Err(Groth16Error::GeneralError(Error::InvalidData));
        }

        // Parse G1 alpha (uncompressed).
        let g1_alpha = SAffineG1::from_uncompressed_bytes(&bytes[0..64])?;

        // Parse G2 beta, gamma, delta (uncompressed).
        let g2_beta_point = SAffineG2::from_uncompressed_bytes(&bytes[64..192])?;
        let g2_gamma = SAffineG2::from_uncompressed_bytes(&bytes[192..256])?;
        let g2_delta = SAffineG2::from_uncompressed_bytes(&bytes[256..384])?;

        // Negate beta for the verifier's purpose.
        let neg_g2_beta = SAffineG2(
            AffineG2::from_jacobian(-G2::from(g2_beta_point.0)).ok_or(Error::InvalidPoint)?,
        );

        // Read the number of K points (u32, big‐endian).
        let num_k = u32::from_be_bytes([bytes[384], bytes[385], bytes[386], bytes[387]]);

        // Validate buffer size
        let expected_size = 388 + (num_k as usize * 64);
        if bytes.len() != expected_size {
            return Err(Groth16Error::GeneralError(Error::InvalidData));
        }

        let mut k = Vec::with_capacity(num_k as usize);
        let mut offset = 388;
        for _ in 0..num_k {
            let point = SAffineG1::from_uncompressed_bytes(&bytes[offset..offset + 64])?;
            k.push(point);
            offset += 64;
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
}

#[cfg(test)]
mod tests {
    use sp1_verifier::GROTH16_VK_BYTES;

    use super::*;

    #[test]
    fn test_vk_serde() {
        let vk = Groth16VerifyingKey::load_from_gnark_bytes(&GROTH16_VK_BYTES).unwrap();

        // Pretty print the JSON output
        let json_string = serde_json::to_string_pretty(&vk).unwrap();
        println!("Groth16VerifyingKey JSON output:");
        println!("{}", json_string);

        let serialized = serde_json::to_vec(&vk).unwrap();
        let deserialized: Groth16VerifyingKey = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(vk, deserialized);
    }

    #[test]
    fn test_vk_bincode_serde() {
        let vk = Groth16VerifyingKey::load_from_gnark_bytes(&GROTH16_VK_BYTES).unwrap();

        let serialized = bincode::serialize(&vk).unwrap();
        let deserialized: Groth16VerifyingKey = bincode::deserialize(&serialized).unwrap();

        assert_eq!(vk, deserialized);
    }

    #[test]
    fn test_vk_borsh() {
        let vk = Groth16VerifyingKey::load_from_gnark_bytes(&GROTH16_VK_BYTES).unwrap();

        let serialized = borsh::to_vec(&vk).unwrap();
        let deserialized: Groth16VerifyingKey = borsh::from_slice(&serialized).unwrap();

        assert_eq!(vk, deserialized);
    }
}
