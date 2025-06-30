use std::fmt;

use bn::{AffineG1, Fq, G1, Group};
use serde::{Deserialize, Serialize, Serializer};

use crate::{
    error::Error,
    utils::{bytes_to_hex, hex_to_bytes},
};

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SAffineG1(pub AffineG1);

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

#[derive(Serialize, Deserialize)]
struct SAffineG1Helper {
    x: String,
    y: String,
}

impl From<&SAffineG1> for SAffineG1Helper {
    fn from(value: &SAffineG1) -> Self {
        // Convert to projective to access coordinates
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
    type Error = Error;
    fn try_from(value: SAffineG1Helper) -> Result<Self, Self::Error> {
        let x = deserialize_fq_from_hex(&value.x)?;
        let y = deserialize_fq_from_hex(&value.y)?;
        let z = Fq::one();

        let projective = G1::new(x, y, z);

        let g1 = AffineG1::from_jacobian(projective).ok_or(Error::InvalidPoint)?;
        Ok(SAffineG1(g1))
    }
}

impl Serialize for SAffineG1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SAffineG1Helper::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SAffineG1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = SAffineG1Helper::deserialize(deserializer)?;
        SAffineG1::try_from(helper).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for SAffineG1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let helper = SAffineG1Helper::from(self);
        f.debug_struct("AffineG1")
            .field("x", &helper.x)
            .field("y", &helper.y)
            .finish()
    }
}

// Helper functions for Fq serialization
pub(super) fn serialize_fq_to_hex(fq: &Fq) -> String {
    let mut slice = [0u8; 32];
    // NOTE: It is safe to unwrap because the only error is if size of slice is not of length 32.
    fq.to_big_endian(&mut slice).unwrap();
    bytes_to_hex(&slice)
}

pub(super) fn deserialize_fq_from_hex(hex_str: &str) -> Result<Fq, Error> {
    let bytes = hex_to_bytes(hex_str)?;
    Fq::from_slice(&bytes).map_err(Error::Field)
}
