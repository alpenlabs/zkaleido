//! Serde serialization implementations for Groth16 types.
//!
//! This module provides custom serde serialization and deserialization
//! for elliptic curve points and Groth16 proof structures.
//!
//! ## Serialization Formats
//!
//! The implementation supports two serialization strategies:
//!
//! - **Human-readable formats** (JSON, TOML, etc.): Uses hex-encoded strings for field elements and
//!   structured representations for complex types
//! - **Binary formats** (bincode, MessagePack, etc.): Uses raw uncompressed byte representations
//!   for efficient storage and transmission

use bn::{Fq, Fq2, Group, G1, G2};
use serde::{
    de::Error as DeError, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{
    error::{BufferLengthError, InvalidDataFormatError, InvalidPointError, SerializationError},
    types::{
        constant::{FQ_SIZE, G1_UNCOMPRESSED_SIZE, G2_UNCOMPRESSED_SIZE},
        g1::SAffineG1,
        g2::SAffineG2,
        proof::Groth16Proof,
        vk::{Groth16G1, Groth16G2, Groth16VerifyingKey},
    },
    verifier::SP1Groth16Verifier,
};

// Helper structures for SAffineG1
#[derive(Serialize, Deserialize)]
struct SAffineG1Helper {
    x: String,
    y: String,
}

// Helper structures for SAffineG2
#[derive(Debug, Serialize, Deserialize)]
struct SAffineG2Helper {
    x: Fq2Helper,
    y: Fq2Helper,
}

#[derive(Debug, Serialize, Deserialize)]
struct Fq2Helper {
    real: String,
    imaginary: String,
}

impl From<&SAffineG1> for SAffineG1Helper {
    fn from(value: &SAffineG1) -> Self {
        let mut projective: G1 = (value.0).into();
        projective.normalize();
        let (x, y) = (projective.x(), projective.y());

        SAffineG1Helper {
            x: serialize_fq_to_hex(&x),
            y: serialize_fq_to_hex(&y),
        }
    }
}

impl TryFrom<SAffineG1Helper> for SAffineG1 {
    type Error = SerializationError;

    fn try_from(value: SAffineG1Helper) -> Result<Self, Self::Error> {
        let x = deserialize_fq_from_hex(&value.x)?;
        let y = deserialize_fq_from_hex(&value.y)?;
        let z = Fq::one();

        let projective = G1::new(x, y, z);

        let g1 = bn::AffineG1::from_jacobian(projective).ok_or(InvalidPointError)?;
        Ok(SAffineG1(g1))
    }
}

impl Serialize for SAffineG1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // For human-readable formats (JSON, TOML, etc.), use hex strings
            SAffineG1Helper::from(self).serialize(serializer)
        } else {
            // For binary formats (bincode, etc.), use raw bytes
            self.to_uncompressed_bytes().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for SAffineG1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // For human-readable formats (JSON, TOML, etc.), parse from hex strings
            let helper = SAffineG1Helper::deserialize(deserializer)?;
            SAffineG1::try_from(helper).map_err(DeError::custom)
        } else {
            // For binary formats (bincode, etc.), parse from raw bytes
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            if bytes.len() != G1_UNCOMPRESSED_SIZE {
                return Err(DeError::custom(format!(
                    "Expected {} bytes for SAffineG1, got {}",
                    G1_UNCOMPRESSED_SIZE,
                    bytes.len()
                )));
            }
            let mut array = [0u8; G1_UNCOMPRESSED_SIZE];
            array.copy_from_slice(&bytes);
            SAffineG1::from_uncompressed_bytes(&array).map_err(DeError::custom)
        }
    }
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
    type Error = SerializationError;

    fn try_from(value: SAffineG2Helper) -> Result<Self, Self::Error> {
        let x = deserialize_fq2_from_hex(&value.x)?;
        let y = deserialize_fq2_from_hex(&value.y)?;
        let z = Fq2::one();

        let projective = G2::new(x, y, z);

        let g2 = bn::AffineG2::from_jacobian(projective).ok_or(InvalidPointError)?;
        Ok(SAffineG2(g2))
    }
}

impl Serialize for SAffineG2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // For human-readable formats (JSON, TOML, etc.), use hex strings
            SAffineG2Helper::from(self).serialize(serializer)
        } else {
            // For binary formats (bincode, etc.), use raw bytes
            self.to_uncompressed_bytes().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for SAffineG2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // For human-readable formats (JSON, TOML, etc.), parse from hex strings
            let helper = SAffineG2Helper::deserialize(deserializer)?;
            SAffineG2::try_from(helper).map_err(DeError::custom)
        } else {
            // For binary formats (bincode, etc.), parse from raw bytes
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            if bytes.len() != G2_UNCOMPRESSED_SIZE {
                return Err(DeError::custom(format!(
                    "Expected {} bytes for SAffineG2, got {}",
                    G2_UNCOMPRESSED_SIZE,
                    bytes.len()
                )));
            }
            let mut array = [0u8; G2_UNCOMPRESSED_SIZE];
            array.copy_from_slice(&bytes);
            SAffineG2::from_uncompressed_bytes(&array).map_err(DeError::custom)
        }
    }
}

// Helper functions for Fq serialization
pub(crate) fn serialize_fq_to_hex(fq: &Fq) -> String {
    let mut slice = [0u8; FQ_SIZE];
    // NOTE: It is safe to unwrap because the only error is if size of slice is not of length
    // FQ_SIZE.
    fq.to_big_endian(&mut slice).unwrap();
    fq_bytes_to_hex_string(&slice)
}

pub(crate) fn deserialize_fq_from_hex(hex_str: &str) -> Result<Fq, SerializationError> {
    let bytes = hex_string_to_fq_bytes(hex_str)?;
    Fq::from_slice(&bytes).map_err(Into::into)
}

fn serialize_fq2_to_hex(fq2: &Fq2) -> Fq2Helper {
    let real = fq2.real();
    let imaginary = fq2.imaginary();

    let real = serialize_fq_to_hex(&real);
    let imaginary = serialize_fq_to_hex(&imaginary);

    Fq2Helper { real, imaginary }
}

fn deserialize_fq2_from_hex(hex: &Fq2Helper) -> Result<Fq2, SerializationError> {
    let real = deserialize_fq_from_hex(&hex.real)?;
    let imaginary = deserialize_fq_from_hex(&hex.imaginary)?;
    Ok(Fq2::new(real, imaginary))
}

// Derive implementations for composite types
impl Serialize for Groth16Proof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Groth16Proof", 3)?;
        state.serialize_field("ar", &self.ar)?;
        state.serialize_field("krs", &self.krs)?;
        state.serialize_field("bs", &self.bs)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Groth16Proof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Groth16ProofHelper {
            ar: SAffineG1,
            krs: SAffineG1,
            bs: SAffineG2,
        }

        let helper = Groth16ProofHelper::deserialize(deserializer)?;
        Ok(Groth16Proof {
            ar: helper.ar,
            krs: helper.krs,
            bs: helper.bs,
        })
    }
}

impl Serialize for Groth16G1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Groth16G1", 2)?;
        state.serialize_field("alpha", &self.alpha)?;
        state.serialize_field("k", &self.k)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Groth16G1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Groth16G1Helper {
            alpha: SAffineG1,
            k: Vec<SAffineG1>,
        }

        let helper = Groth16G1Helper::deserialize(deserializer)?;
        Ok(Groth16G1 {
            alpha: helper.alpha,
            k: helper.k,
        })
    }
}

impl Serialize for Groth16G2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Groth16G2", 3)?;
        state.serialize_field("beta", &self.beta)?;
        state.serialize_field("delta", &self.delta)?;
        state.serialize_field("gamma", &self.gamma)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Groth16G2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Groth16G2Helper {
            beta: SAffineG2,
            delta: SAffineG2,
            gamma: SAffineG2,
        }

        let helper = Groth16G2Helper::deserialize(deserializer)?;
        Ok(Groth16G2 {
            beta: helper.beta,
            delta: helper.delta,
            gamma: helper.gamma,
        })
    }
}

impl Serialize for Groth16VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Groth16VerifyingKey", 2)?;
        state.serialize_field("g1", &self.g1)?;
        state.serialize_field("g2", &self.g2)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Groth16VerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Groth16VerifyingKeyHelper {
            g1: Groth16G1,
            g2: Groth16G2,
        }

        let helper = Groth16VerifyingKeyHelper::deserialize(deserializer)?;
        Ok(Groth16VerifyingKey {
            g1: helper.g1,
            g2: helper.g2,
        })
    }
}

impl Serialize for SP1Groth16Verifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SP1Groth16Verifier", 2)?;
        state.serialize_field("vk", &self.vk)?;
        state.serialize_field("vk_hash_tag", &self.vk_hash_tag)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SP1Groth16Verifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SP1Groth16VerifierHelper {
            vk: Groth16VerifyingKey,
            vk_hash_tag: [u8; 4],
        }

        let helper = SP1Groth16VerifierHelper::deserialize(deserializer)?;
        Ok(SP1Groth16Verifier {
            vk: helper.vk,
            vk_hash_tag: helper.vk_hash_tag,
        })
    }
}

// Helper functions for hex conversion
fn fq_bytes_to_hex_string(bytes: &[u8; FQ_SIZE]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex_string_to_fq_bytes(hex_str: &str) -> Result<[u8; FQ_SIZE], SerializationError> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|_| InvalidDataFormatError)?;
    if bytes.len() != FQ_SIZE {
        return Err(BufferLengthError {
            context: "Fq",
            expected: FQ_SIZE,
            actual: bytes.len(),
        }
        .into());
    }
    let mut array = [0u8; FQ_SIZE];
    array.copy_from_slice(&bytes);
    Ok(array)
}

#[cfg(test)]
mod tests {
    use sp1_verifier::GROTH16_VK_BYTES;

    use crate::types::vk::Groth16VerifyingKey;

    #[test]
    fn test_vk_serde_json() {
        let vk = Groth16VerifyingKey::from_gnark_bytes(&GROTH16_VK_BYTES).unwrap();

        // Pretty print the JSON output
        let json_string = serde_json::to_string_pretty(&vk).unwrap();
        println!("Groth16VerifyingKey JSON output:");
        println!("{}", json_string);

        let serialized = serde_json::to_vec(&vk).unwrap();
        let deserialized: Groth16VerifyingKey = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(vk, deserialized);
    }

    #[test]
    fn test_vk_serde_bincode() {
        let vk = Groth16VerifyingKey::from_gnark_bytes(&GROTH16_VK_BYTES).unwrap();

        let serialized = bincode::serialize(&vk).unwrap();
        let deserialized: Groth16VerifyingKey = bincode::deserialize(&serialized).unwrap();

        assert_eq!(vk, deserialized);
    }

    #[test]
    fn test_serialization_format_differences() {
        let vk = Groth16VerifyingKey::from_gnark_bytes(&GROTH16_VK_BYTES).unwrap();

        // Test JSON (human-readable) format
        let json_serialized = serde_json::to_string(&vk).unwrap();
        // JSON should contain hex strings
        assert!(json_serialized.contains("0x"));
        assert!(json_serialized.contains("\"x\""));
        assert!(json_serialized.contains("\"y\""));

        // Test bincode (binary) format
        let bincode_serialized = bincode::serialize(&vk).unwrap();
        // Bincode should be more compact and contain raw bytes
        // It should NOT contain hex strings when inspected as UTF-8
        let bincode_as_string = String::from_utf8_lossy(&bincode_serialized);
        assert!(!bincode_as_string.contains("0x"));

        // Verify both formats can deserialize correctly
        let json_deserialized: Groth16VerifyingKey =
            serde_json::from_str(&json_serialized).unwrap();
        let bincode_deserialized: Groth16VerifyingKey =
            bincode::deserialize(&bincode_serialized).unwrap();

        assert_eq!(vk, json_deserialized);
        assert_eq!(vk, bincode_deserialized);
        assert_eq!(json_deserialized, bincode_deserialized);
    }
}
