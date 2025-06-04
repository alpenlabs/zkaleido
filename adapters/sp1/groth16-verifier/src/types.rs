use std::io::{Error, ErrorKind, Read, Result, Write};

use bn::{arith::U256, AffineG1, AffineG2, Fq, Fq2, G1, G2};
use borsh::{BorshDeserialize, BorshSerialize};

/// G1 elements of the verification key.
#[derive(Clone, PartialEq)]
pub(crate) struct Groth16G1 {
    pub(crate) alpha: AffineG1,
    pub(crate) k: Vec<AffineG1>,
}

/// G2 elements of the verification key.
#[derive(Clone, PartialEq)]
pub(crate) struct Groth16G2 {
    pub(crate) beta: AffineG2,
    pub(crate) delta: AffineG2,
    pub(crate) gamma: AffineG2,
}

/// Verification key for the Groth16 proof.
#[derive(Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub(crate) struct Groth16VerifyingKey {
    pub(crate) g1: Groth16G1,
    pub(crate) g2: Groth16G2,
}

/// Proof for the Groth16 verification.
pub(crate) struct Groth16Proof {
    pub(crate) ar: AffineG1,
    pub(crate) krs: AffineG1,
    pub(crate) bs: AffineG2,
}

// Direct serialization for Groth16G1
impl BorshSerialize for Groth16G1 {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Serialize alpha
        serialize_affine_g1(&self.alpha, writer)?;

        // Serialize k vector
        (self.k.len() as u32).serialize(writer)?;
        for point in &self.k {
            serialize_affine_g1(point, writer)?;
        }

        Ok(())
    }
}

impl BorshDeserialize for Groth16G1 {
    fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self> {
        // Deserialize alpha
        let alpha = deserialize_affine_g1(reader)?;

        // Deserialize k vector
        let k_len = u32::deserialize_reader(reader)? as usize;
        let mut k = Vec::with_capacity(k_len);
        for _ in 0..k_len {
            k.push(deserialize_affine_g1(reader)?);
        }

        Ok(Groth16G1 { alpha, k })
    }
}

// Direct serialization for Groth16G2
impl BorshSerialize for Groth16G2 {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        serialize_affine_g2(&self.beta, writer)?;
        serialize_affine_g2(&self.delta, writer)?;
        serialize_affine_g2(&self.gamma, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for Groth16G2 {
    fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self> {
        let beta = deserialize_affine_g2(reader)?;
        let delta = deserialize_affine_g2(reader)?;
        let gamma = deserialize_affine_g2(reader)?;

        Ok(Groth16G2 { beta, delta, gamma })
    }
}

// Helper functions for AffineG1 serialization
fn serialize_affine_g1<W: Write>(point: &AffineG1, writer: &mut W) -> Result<()> {
    // Convert to projective to access coordinates
    let projective: G1 = (*point).into();
    let (x, y, z) = (projective.x(), projective.y(), projective.z());

    // Serialize as 32-byte big-endian arrays
    serialize_fq(&x, writer)?;
    serialize_fq(&y, writer)?;
    serialize_fq(&z, writer)?;

    Ok(())
}

fn deserialize_affine_g1<R: Read>(reader: &mut R) -> Result<AffineG1> {
    let x = deserialize_fq(reader)?;
    let y = deserialize_fq(reader)?;
    let z = deserialize_fq(reader)?;

    // Reconstruct point
    let projective = G1::new(x, y, z);
    AffineG1::from_jacobian(projective).ok_or(Error::new(ErrorKind::InvalidData, "Invalid g1"))
}

// Helper functions for AffineG2 serialization
fn serialize_affine_g2<W: Write>(point: &AffineG2, writer: &mut W) -> Result<()> {
    let projective: G2 = (*point).into();
    let (x, y, z) = (projective.x(), projective.y(), projective.z());

    serialize_fq2(&x, writer)?;
    serialize_fq2(&y, writer)?;
    serialize_fq2(&z, writer)?;

    Ok(())
}

fn deserialize_affine_g2<R: Read>(reader: &mut R) -> Result<AffineG2> {
    let x = deserialize_fq2(reader)?;
    let y = deserialize_fq2(reader)?;
    let z = deserialize_fq2(reader)?;

    let projective = G2::new(x, y, z);
    AffineG2::from_jacobian(projective).ok_or(Error::new(ErrorKind::InvalidData, "Invalid g2"))
}

// Helper functions for Fq serialization
fn serialize_fq<W: Write>(fq: &Fq, writer: &mut W) -> Result<()> {
    let [first, second] = fq.into_u256().0;
    first.serialize(writer)?;
    second.serialize(writer)?;
    Ok(())
}

fn deserialize_fq<R: Read>(reader: &mut R) -> Result<Fq> {
    let first = u128::deserialize_reader(reader)?;
    let second = u128::deserialize_reader(reader)?;
    Fq::from_u256(U256([first, second]))
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid Fq "))
}

// Helper functions for Fq serialization
fn serialize_fq2<W: Write>(fq2: &Fq2, writer: &mut W) -> Result<()> {
    let (real, imaginary) = (fq2.real(), fq2.imaginary());
    serialize_fq(&real, writer)?;
    serialize_fq(&imaginary, writer)?;
    Ok(())
}

fn deserialize_fq2<R: Read>(reader: &mut R) -> Result<Fq2> {
    let real = deserialize_fq(reader)?;
    let imaginary = deserialize_fq(reader)?;
    Ok(Fq2::new(real, imaginary))
}

#[cfg(test)]
mod tests {
    use sp1_verifier::GROTH16_VK_BYTES;

    use crate::{conversion::load_groth16_verifying_key_from_bytes, types::Groth16VerifyingKey};

    #[test]
    fn test_vk_borsh_serde() {
        let vk = load_groth16_verifying_key_from_bytes(&GROTH16_VK_BYTES).unwrap();

        let serialized = borsh::to_vec(&vk).unwrap();
        let deserialized: Groth16VerifyingKey = borsh::from_slice(&serialized).unwrap();

        assert!(vk == deserialized);
    }
}
