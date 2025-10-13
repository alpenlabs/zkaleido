//! Borsh serialization implementations for Groth16 types.
//!
//! This module provides binary serialization using the Borsh format
//! for elliptic curve points and Groth16 proof structures.

use std::io;

use bn::{Fq, Fq2, Group, G1, G2};
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
        // Convert to projective to access coordinates
        let mut projective: G1 = (self.0).into();
        projective.normalize();
        let (x, y) = (projective.x(), projective.y());

        // Serialize x coordinate
        let mut x_bytes = [0u8; 32];
        x.to_big_endian(&mut x_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to serialize x coordinate",
            )
        })?;
        writer.write_all(&x_bytes)?;

        // Serialize y coordinate
        let mut y_bytes = [0u8; 32];
        y.to_big_endian(&mut y_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to serialize y coordinate",
            )
        })?;
        writer.write_all(&y_bytes)?;

        Ok(())
    }
}

impl BorshDeserialize for SAffineG1 {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        // Read x coordinate
        let mut x_bytes = [0u8; 32];
        reader.read_exact(&mut x_bytes)?;
        let x = Fq::from_slice(&x_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to deserialize x coordinate",
            )
        })?;

        // Read y coordinate
        let mut y_bytes = [0u8; 32];
        reader.read_exact(&mut y_bytes)?;
        let y = Fq::from_slice(&y_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to deserialize y coordinate",
            )
        })?;

        let z = Fq::one();
        let projective = G1::new(x, y, z);
        let g1 = bn::AffineG1::from_jacobian(projective)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid point"))?;

        Ok(SAffineG1(g1))
    }
}

// SAffineG2 borsh implementation
impl BorshSerialize for SAffineG2 {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut projective: G2 = (self.0).into();
        projective.normalize();
        let (x, y) = (projective.x(), projective.y());

        // Serialize x coordinate (Fq2: real + imaginary)
        let mut x_real_bytes = [0u8; 32];
        x.real().to_big_endian(&mut x_real_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to serialize x real part",
            )
        })?;
        writer.write_all(&x_real_bytes)?;

        let mut x_imag_bytes = [0u8; 32];
        x.imaginary()
            .to_big_endian(&mut x_imag_bytes)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to serialize x imaginary part",
                )
            })?;
        writer.write_all(&x_imag_bytes)?;

        // Serialize y coordinate (Fq2: real + imaginary)
        let mut y_real_bytes = [0u8; 32];
        y.real().to_big_endian(&mut y_real_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to serialize y real part",
            )
        })?;
        writer.write_all(&y_real_bytes)?;

        let mut y_imag_bytes = [0u8; 32];
        y.imaginary()
            .to_big_endian(&mut y_imag_bytes)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to serialize y imaginary part",
                )
            })?;
        writer.write_all(&y_imag_bytes)?;

        Ok(())
    }
}

impl BorshDeserialize for SAffineG2 {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        // Read x coordinate components
        let mut x_real_bytes = [0u8; 32];
        reader.read_exact(&mut x_real_bytes)?;
        let x_real = Fq::from_slice(&x_real_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to deserialize x real part",
            )
        })?;

        let mut x_imag_bytes = [0u8; 32];
        reader.read_exact(&mut x_imag_bytes)?;
        let x_imag = Fq::from_slice(&x_imag_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to deserialize x imaginary part",
            )
        })?;

        // Read y coordinate components
        let mut y_real_bytes = [0u8; 32];
        reader.read_exact(&mut y_real_bytes)?;
        let y_real = Fq::from_slice(&y_real_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to deserialize y real part",
            )
        })?;

        let mut y_imag_bytes = [0u8; 32];
        reader.read_exact(&mut y_imag_bytes)?;
        let y_imag = Fq::from_slice(&y_imag_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to deserialize y imaginary part",
            )
        })?;

        let x = Fq2::new(x_real, x_imag);
        let y = Fq2::new(y_real, y_imag);
        let z = Fq2::one();

        let projective = G2::new(x, y, z);
        let g2 = bn::AffineG2::from_jacobian(projective)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid point"))?;

        Ok(SAffineG2(g2))
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
