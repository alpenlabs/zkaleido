//! Arbitrary implementations for Groth16 types.
//!
//! This module provides `Arbitrary` trait implementations for property-based testing
//! and fuzzing of elliptic curve points and Groth16 proof structures.

use arbitrary::Arbitrary;
use bn::{AffineG1, AffineG2, Group, G1, G2};
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    types::{
        g1::SAffineG1,
        g2::SAffineG2,
        proof::Groth16Proof,
        vk::{Groth16G1, Groth16G2, Groth16VerifyingKey},
    },
    verifier::SP1Groth16Verifier,
};

impl<'a> Arbitrary<'a> for SAffineG1 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Use the seed bytes from unstructured data to create a deterministic RNG
        let seed: [u8; 32] = u.arbitrary()?;
        let mut rng = StdRng::from_seed(seed);

        // Generate a random G1 point
        let mut g1 = G1::random(&mut rng);
        g1.normalize();

        // Convert to AffineG1 and wrap in SAffineG1
        let affine =
            AffineG1::new(g1.x(), g1.y()).map_err(|_| arbitrary::Error::IncorrectFormat)?;
        Ok(SAffineG1(affine))
    }
}

impl<'a> Arbitrary<'a> for SAffineG2 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Use the seed bytes from unstructured data to create a deterministic RNG
        let seed: [u8; 32] = u.arbitrary()?;
        let mut rng = StdRng::from_seed(seed);

        // Generate a random G2 point
        let mut g2 = G2::random(&mut rng);
        g2.normalize();

        // Convert to AffineG2 and wrap in SAffineG2
        let affine =
            AffineG2::new(g2.x(), g2.y()).map_err(|_| arbitrary::Error::IncorrectFormat)?;
        Ok(SAffineG2(affine))
    }
}

impl<'a> Arbitrary<'a> for Groth16Proof {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Groth16Proof {
            ar: SAffineG1::arbitrary(u)?,
            krs: SAffineG1::arbitrary(u)?,
            bs: SAffineG2::arbitrary(u)?,
        })
    }
}

impl<'a> Arbitrary<'a> for Groth16G1 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Groth16G1 {
            alpha: SAffineG1::arbitrary(u)?,
            k: Vec::<SAffineG1>::arbitrary(u)?,
        })
    }
}

impl<'a> Arbitrary<'a> for Groth16G2 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Groth16G2 {
            beta: SAffineG2::arbitrary(u)?,
            delta: SAffineG2::arbitrary(u)?,
            gamma: SAffineG2::arbitrary(u)?,
        })
    }
}

impl<'a> Arbitrary<'a> for Groth16VerifyingKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Groth16VerifyingKey {
            g1: Groth16G1::arbitrary(u)?,
            g2: Groth16G2::arbitrary(u)?,
        })
    }
}

impl<'a> Arbitrary<'a> for SP1Groth16Verifier {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(SP1Groth16Verifier {
            vk: Groth16VerifyingKey::arbitrary(u)?,
            vk_hash_tag: <[u8; 4]>::arbitrary(u)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use arbitrary::Arbitrary;

    use super::*;

    #[test]
    fn test_arbitrary_saffine_g1() {
        let data = vec![0u8; 1024];
        let mut u = arbitrary::Unstructured::new(&data);
        let g1 = SAffineG1::arbitrary(&mut u).unwrap();

        // Verify the point can be serialized and deserialized
        let bytes = g1.to_uncompressed_bytes();
        let recovered = SAffineG1::from_uncompressed_bytes(&bytes).unwrap();
        assert_eq!(g1, recovered);
    }

    #[test]
    fn test_arbitrary_saffine_g2() {
        let data = vec![0u8; 1024];
        let mut u = arbitrary::Unstructured::new(&data);
        let g2 = SAffineG2::arbitrary(&mut u).unwrap();

        // Verify the point can be serialized and deserialized
        let bytes = g2.to_uncompressed_bytes();
        let recovered = SAffineG2::from_uncompressed_bytes(&bytes).unwrap();
        assert_eq!(g2, recovered);
    }

    #[test]
    fn test_arbitrary_groth16_proof() {
        let data = vec![0u8; 4096];
        let mut u = arbitrary::Unstructured::new(&data);
        let proof = Groth16Proof::arbitrary(&mut u).unwrap();

        // Verify we got valid points
        assert_ne!(proof.ar.to_uncompressed_bytes(), [0u8; 64]);
        assert_ne!(proof.krs.to_uncompressed_bytes(), [0u8; 64]);
        assert_ne!(proof.bs.to_uncompressed_bytes(), [0u8; 128]);
    }

    #[test]
    fn test_arbitrary_groth16_verifying_key() {
        let data = vec![0u8; 8192];
        let mut u = arbitrary::Unstructured::new(&data);
        let vk = Groth16VerifyingKey::arbitrary(&mut u).unwrap();

        // Verify we got valid structures
        assert_ne!(vk.g1.alpha.to_uncompressed_bytes(), [0u8; 64]);
        assert_ne!(vk.g2.beta.to_uncompressed_bytes(), [0u8; 128]);
    }

    #[test]
    fn test_arbitrary_sp1_groth16_verifier() {
        let data = vec![0u8; 8192];
        let mut u = arbitrary::Unstructured::new(&data);
        let verifier = SP1Groth16Verifier::arbitrary(&mut u).unwrap();

        // Verify we got a valid verifier with a 4-byte tag
        assert_eq!(verifier.vk_hash_tag.len(), 4);
    }
}
