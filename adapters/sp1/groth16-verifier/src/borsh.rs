//! Borsh serialization implementations for Groth16 types.
//!
//! This module provides binary serialization using the Borsh format
//! for elliptic curve points and Groth16 proof structures.
//!
//! The serialization uses uncompressed bytes format directly via the existing
//! `to_uncompressed_bytes()` and `from_uncompressed_bytes()` methods on G1/G2 points.
//! This avoids manual coordinate manipulation and leverages the optimized
//! serialization/deserialization routines already implemented for the types.

use std::io;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    types::{
        g1::SAffineG1,
        g2::SAffineG2,
        proof::Groth16Proof,
        vk::{Groth16G1, Groth16G2, Groth16VerifyingKey},
    },
    verifier::SP1Groth16Verifier,
};

// SAffineG1 borsh implementation
impl BorshSerialize for SAffineG1 {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        let bytes = self.to_uncompressed_bytes();
        writer.write_all(&bytes)
    }
}

impl BorshDeserialize for SAffineG1 {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let mut bytes = [0u8; 64];
        reader.read_exact(&mut bytes)?;
        SAffineG1::from_uncompressed_bytes(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

// SAffineG2 borsh implementation
impl BorshSerialize for SAffineG2 {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        let bytes = self.to_uncompressed_bytes();
        writer.write_all(&bytes)
    }
}

impl BorshDeserialize for SAffineG2 {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let mut bytes = [0u8; 128];
        reader.read_exact(&mut bytes)?;
        SAffineG2::from_uncompressed_bytes(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

// Derive implementations for composite types using borsh's built-in support
impl BorshSerialize for Groth16Proof {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        self.ar.serialize(writer)?;
        self.krs.serialize(writer)?;
        self.bs.serialize(writer)?;
        Ok(())
    }
}

impl BorshDeserialize for Groth16Proof {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let ar = SAffineG1::deserialize_reader(reader)?;
        let krs = SAffineG1::deserialize_reader(reader)?;
        let bs = SAffineG2::deserialize_reader(reader)?;
        Ok(Groth16Proof { ar, krs, bs })
    }
}

impl BorshSerialize for Groth16G1 {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        self.alpha.serialize(writer)?;
        self.k.serialize(writer)?;
        Ok(())
    }
}

impl BorshDeserialize for Groth16G1 {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let alpha = SAffineG1::deserialize_reader(reader)?;
        let k = Vec::<SAffineG1>::deserialize_reader(reader)?;
        Ok(Groth16G1 { alpha, k })
    }
}

impl BorshSerialize for Groth16G2 {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        self.beta.serialize(writer)?;
        self.delta.serialize(writer)?;
        self.gamma.serialize(writer)?;
        Ok(())
    }
}

impl BorshDeserialize for Groth16G2 {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let beta = SAffineG2::deserialize_reader(reader)?;
        let delta = SAffineG2::deserialize_reader(reader)?;
        let gamma = SAffineG2::deserialize_reader(reader)?;
        Ok(Groth16G2 { beta, delta, gamma })
    }
}

impl BorshSerialize for Groth16VerifyingKey {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        self.g1.serialize(writer)?;
        self.g2.serialize(writer)?;
        Ok(())
    }
}

impl BorshDeserialize for Groth16VerifyingKey {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let g1 = Groth16G1::deserialize_reader(reader)?;
        let g2 = Groth16G2::deserialize_reader(reader)?;
        Ok(Groth16VerifyingKey { g1, g2 })
    }
}

impl BorshSerialize for SP1Groth16Verifier {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        self.vk.serialize(writer)?;
        self.vk_hash_tag.serialize(writer)?;
        Ok(())
    }
}

impl BorshDeserialize for SP1Groth16Verifier {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let vk = Groth16VerifyingKey::deserialize_reader(reader)?;
        let vk_hash_tag = <[u8; 4]>::deserialize_reader(reader)?;
        Ok(SP1Groth16Verifier { vk, vk_hash_tag })
    }
}

#[cfg(test)]
mod tests {
    use sp1_verifier::GROTH16_VK_BYTES;

    use crate::types::vk::Groth16VerifyingKey;

    #[test]
    fn test_vk_borsh() {
        let vk = Groth16VerifyingKey::load_from_gnark_bytes(&GROTH16_VK_BYTES).unwrap();

        let serialized = borsh::to_vec(&vk).unwrap();
        let deserialized: Groth16VerifyingKey = borsh::from_slice(&serialized).unwrap();

        assert_eq!(vk, deserialized);
    }
}
