use std::{
    fmt::{self, Debug, Formatter},
    io::{Error, ErrorKind},
};

use bn::{arith::U256, AffineG1, AffineG2, Fq, Fq2, G1, G2};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// G1 elements of the verification key.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Groth16G1 {
    #[serde(
        serialize_with = "serialize_affine_g1",
        deserialize_with = "deserialize_affine_g1"
    )]
    pub(crate) alpha: AffineG1,
    #[serde(
        serialize_with = "serialize_affine_g1_vec",
        deserialize_with = "deserialize_affine_g1_vec"
    )]
    pub(crate) k: Vec<AffineG1>,
}

/// G2 elements of the verification key.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Groth16G2 {
    #[serde(
        serialize_with = "serialize_affine_g2",
        deserialize_with = "deserialize_affine_g2"
    )]
    pub(crate) beta: AffineG2,
    #[serde(
        serialize_with = "serialize_affine_g2",
        deserialize_with = "deserialize_affine_g2"
    )]
    pub(crate) delta: AffineG2,
    #[serde(
        serialize_with = "serialize_affine_g2",
        deserialize_with = "deserialize_affine_g2"
    )]
    pub(crate) gamma: AffineG2,
}

/// Verification key for the Groth16 proof.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Groth16VerifyingKey {
    pub(crate) g1: Groth16G1,
    pub(crate) g2: Groth16G2,
}

/// Proof for the Groth16 verification.
#[derive(Serialize, Deserialize)]
pub(crate) struct Groth16Proof {
    #[serde(
        serialize_with = "serialize_affine_g1",
        deserialize_with = "deserialize_affine_g1"
    )]
    pub(crate) ar: AffineG1,
    #[serde(
        serialize_with = "serialize_affine_g1",
        deserialize_with = "deserialize_affine_g1"
    )]
    pub(crate) krs: AffineG1,
    #[serde(
        serialize_with = "serialize_affine_g2",
        deserialize_with = "deserialize_affine_g2"
    )]
    pub(crate) bs: AffineG2,
}

// Serde serialization for AffineG1
fn serialize_affine_g1<S>(point: &AffineG1, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Convert to projective to access coordinates
    let projective: G1 = (*point).into();
    let (x, y, z) = (projective.x(), projective.y(), projective.z());

    let hex_strings = [
        bytes_to_hex(&serialize_fq_to_bytes(&x)),
        bytes_to_hex(&serialize_fq_to_bytes(&y)),
        bytes_to_hex(&serialize_fq_to_bytes(&z)),
    ];

    hex_strings.serialize(serializer)
}

fn deserialize_affine_g1<'de, D>(deserializer: D) -> Result<AffineG1, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_strings: [String; 3] = Deserialize::deserialize(deserializer)?;

    let x_bytes = hex_to_bytes(&hex_strings[0]).map_err(serde::de::Error::custom)?;
    let y_bytes = hex_to_bytes(&hex_strings[1]).map_err(serde::de::Error::custom)?;
    let z_bytes = hex_to_bytes(&hex_strings[2]).map_err(serde::de::Error::custom)?;

    let x = deserialize_fq_from_bytes(&x_bytes).map_err(serde::de::Error::custom)?;
    let y = deserialize_fq_from_bytes(&y_bytes).map_err(serde::de::Error::custom)?;
    let z = deserialize_fq_from_bytes(&z_bytes).map_err(serde::de::Error::custom)?;

    // Reconstruct point
    let projective = G1::new(x, y, z);
    AffineG1::from_jacobian(projective).ok_or_else(|| serde::de::Error::custom("Invalid G1 point"))
}

// Serde serialization for Vec<AffineG1>
fn serialize_affine_g1_vec<S>(points: &[AffineG1], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let serialized_points: Vec<[String; 3]> = points
        .iter()
        .map(|point| {
            let projective: G1 = (*point).into();
            let (x, y, z) = (projective.x(), projective.y(), projective.z());
            [
                bytes_to_hex(&serialize_fq_to_bytes(&x)),
                bytes_to_hex(&serialize_fq_to_bytes(&y)),
                bytes_to_hex(&serialize_fq_to_bytes(&z)),
            ]
        })
        .collect();

    serialized_points.serialize(serializer)
}

fn deserialize_affine_g1_vec<'de, D>(deserializer: D) -> Result<Vec<AffineG1>, D::Error>
where
    D: Deserializer<'de>,
{
    let serialized_points: Vec<[String; 3]> = Deserialize::deserialize(deserializer)?;

    serialized_points
        .into_iter()
        .map(|hex_strings| {
            let x_bytes = hex_to_bytes(&hex_strings[0]).map_err(serde::de::Error::custom)?;
            let y_bytes = hex_to_bytes(&hex_strings[1]).map_err(serde::de::Error::custom)?;
            let z_bytes = hex_to_bytes(&hex_strings[2]).map_err(serde::de::Error::custom)?;

            let x = deserialize_fq_from_bytes(&x_bytes).map_err(serde::de::Error::custom)?;
            let y = deserialize_fq_from_bytes(&y_bytes).map_err(serde::de::Error::custom)?;
            let z = deserialize_fq_from_bytes(&z_bytes).map_err(serde::de::Error::custom)?;

            let projective = G1::new(x, y, z);
            AffineG1::from_jacobian(projective)
                .ok_or_else(|| serde::de::Error::custom("Invalid G1 point"))
        })
        .collect()
}

// Serde serialization for AffineG2
fn serialize_affine_g2<S>(point: &AffineG2, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let projective: G2 = (*point).into();
    let (x, y, z) = (projective.x(), projective.y(), projective.z());

    let hex_strings = [
        serialize_fq2_to_hex(&x),
        serialize_fq2_to_hex(&y),
        serialize_fq2_to_hex(&z),
    ];

    hex_strings.serialize(serializer)
}

fn deserialize_affine_g2<'de, D>(deserializer: D) -> Result<AffineG2, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_strings: [[String; 2]; 3] = Deserialize::deserialize(deserializer)?;

    let x = deserialize_fq2_from_hex(&hex_strings[0]).map_err(serde::de::Error::custom)?;
    let y = deserialize_fq2_from_hex(&hex_strings[1]).map_err(serde::de::Error::custom)?;
    let z = deserialize_fq2_from_hex(&hex_strings[2]).map_err(serde::de::Error::custom)?;

    let projective = G2::new(x, y, z);
    AffineG2::from_jacobian(projective).ok_or_else(|| serde::de::Error::custom("Invalid G2 point"))
}

// Helper functions for hex conversion
fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex_to_bytes(hex_str: &str) -> Result<[u8; 32], String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

// Helper functions for Fq serialization
fn serialize_fq_to_bytes(fq: &Fq) -> [u8; 32] {
    let [first, second] = fq.into_u256().0;
    let mut bytes = [0u8; 32];
    bytes[0..16].copy_from_slice(&first.to_le_bytes());
    bytes[16..32].copy_from_slice(&second.to_le_bytes());
    bytes
}

fn deserialize_fq_from_bytes(bytes: &[u8; 32]) -> Result<Fq, Error> {
    let first = u128::from_le_bytes(bytes[0..16].try_into().unwrap());
    let second = u128::from_le_bytes(bytes[16..32].try_into().unwrap());
    Fq::from_u256(U256([first, second]))
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid Fq"))
}

// Helper functions for Fq2 serialization
fn serialize_fq2_to_hex(fq2: &Fq2) -> [String; 2] {
    let (real, imaginary) = (fq2.real(), fq2.imaginary());
    [
        bytes_to_hex(&serialize_fq_to_bytes(&real)),
        bytes_to_hex(&serialize_fq_to_bytes(&imaginary)),
    ]
}

fn deserialize_fq2_from_hex(hex_strings: &[String; 2]) -> Result<Fq2, Error> {
    let real_bytes =
        hex_to_bytes(&hex_strings[0]).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    let imaginary_bytes =
        hex_to_bytes(&hex_strings[1]).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

    let real = deserialize_fq_from_bytes(&real_bytes)?;
    let imaginary = deserialize_fq_from_bytes(&imaginary_bytes)?;
    Ok(Fq2::new(real, imaginary))
}

impl Debug for Groth16G1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Groth16G1")
            .field("alpha", &self.alpha) // AffineG1 already implements Debug
            .field("k", &self.k) // Vec<AffineG1> implements Debug
            .finish()
    }
}

impl Debug for Groth16G2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Groth16G2")
            // We call `{:?}` on the inner `groups::AffineG2` via `self.beta.0`
            .field("beta_x", &format_args!("{:?}", self.beta.x()))
            .field("beta_y", &format_args!("{:?}", self.beta.y()))
            .field("delta_x", &format_args!("{:?}", self.delta.x()))
            .field("delta_y", &format_args!("{:?}", self.delta.y()))
            .field("gamma_x", &format_args!("{:?}", self.gamma.x()))
            .field("gamma_y", &format_args!("{:?}", self.gamma.y()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use sp1_verifier::GROTH16_VK_BYTES;

    use crate::{gnark_conversion::load_groth16_verifying_key_from_bytes, types::Groth16VerifyingKey};

    #[test]
    fn test_vk_serde() {
        let vk = load_groth16_verifying_key_from_bytes(&GROTH16_VK_BYTES).unwrap();

        let serialized = serde_json::to_vec(&vk).unwrap();
        let deserialized: Groth16VerifyingKey = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(vk, deserialized);
    }

    #[test]
    fn test_vk_json_output() {
        let vk = load_groth16_verifying_key_from_bytes(&GROTH16_VK_BYTES).unwrap();

        // Pretty print the JSON output
        let json_string = serde_json::to_string_pretty(&vk).unwrap();
        println!("Groth16VerifyingKey JSON output:");
        println!("{}", json_string);

        // Also show the compact version size
        let compact_json = serde_json::to_string(&vk).unwrap();
        println!("\nCompact JSON size: {} bytes", compact_json.len());
        println!("Pretty JSON size: {} bytes", json_string.len());

        // Verify deserialization works
        let deserialized: Groth16VerifyingKey = serde_json::from_str(&json_string).unwrap();
        assert_eq!(vk, deserialized);
    }

    #[test]
    fn test_vk_bincode_serde() {
        let vk = load_groth16_verifying_key_from_bytes(&GROTH16_VK_BYTES).unwrap();

        let serialized = bincode::serialize(&vk).unwrap();
        let deserialized: Groth16VerifyingKey = bincode::deserialize(&serialized).unwrap();

        assert_eq!(vk, deserialized);
    }
}
