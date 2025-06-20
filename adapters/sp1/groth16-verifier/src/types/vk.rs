use bn::{AffineG2, G2};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Groth16Error},
    types::{
        g1::{compressed_bytes_to_affine_g1, SAffineG1},
        g2::{compressed_bytes_to_affine_g2, SAffineG2},
    },
};

/// G1 elements of the verification key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Groth16G1 {
    pub(crate) alpha: SAffineG1,
    pub(crate) k: Vec<SAffineG1>,
}

/// G2 elements of the verification key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Groth16G2 {
    pub(crate) beta: SAffineG2,
    pub(crate) delta: SAffineG2,
    pub(crate) gamma: SAffineG2,
}

/// Verification key for the Groth16 proof.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Groth16VerifyingKey {
    pub(crate) g1: Groth16G1,
    pub(crate) g2: Groth16G2,
}

impl Groth16VerifyingKey {
    /// Load a Groth16 verifying key from the GNARK‐style compressed byte slice.
    pub(crate) fn load_from_gnark_bytes(buffer: &[u8]) -> Result<Self, Groth16Error> {
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
}
