use std::fmt;

use bn::{AffineG2, Fq2, G2, Group};
use serde::{Deserialize, Serialize, Serializer};

use crate::{
    error::Error,
    g1::{deserialize_fq_from_hex, serialize_fq_to_hex},
};

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SAffineG2(pub AffineG2);

impl From<AffineG2> for SAffineG2 {
    fn from(value: AffineG2) -> Self {
        SAffineG2(value)
    }
}

impl From<SAffineG2> for G2 {
    fn from(value: SAffineG2) -> Self {
        value.0.into()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SAffineG2Helper {
    x: Fq2Helper,
    y: Fq2Helper,
}

#[derive(Serialize, Deserialize)]
struct Fq2Helper {
    real: String,
    imaginary: String,
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
    type Error = Error;
    fn try_from(value: SAffineG2Helper) -> Result<Self, Self::Error> {
        let x = deserialize_fq2_from_hex(&value.x)?;
        let y = deserialize_fq2_from_hex(&value.y)?;
        let z = Fq2::one();

        let projective = G2::new(x, y, z);

        let g2 = AffineG2::from_jacobian(projective).ok_or(Error::InvalidPoint)?;
        Ok(SAffineG2(g2))
    }
}

impl Serialize for SAffineG2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SAffineG2Helper::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SAffineG2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = SAffineG2Helper::deserialize(deserializer)?;
        SAffineG2::try_from(helper).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for Fq2Helper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fq2")
            .field("x", &self.real)
            .field("y", &self.imaginary)
            .finish()
    }
}

impl fmt::Debug for SAffineG2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let helper = SAffineG2Helper::from(self);
        f.debug_struct("AffineG2")
            .field("x", &helper.x)
            .field("y", &helper.y)
            .finish()
    }
}

fn serialize_fq2_to_hex(fq2: &Fq2) -> Fq2Helper {
    let real = fq2.real();
    let imaginary = fq2.imaginary();

    let real = serialize_fq_to_hex(&real);
    let imaginary = serialize_fq_to_hex(&imaginary);

    Fq2Helper { real, imaginary }
}

fn deserialize_fq2_from_hex(hex: &Fq2Helper) -> Result<Fq2, Error> {
    let real = deserialize_fq_from_hex(&hex.real)?;
    let imaginary = deserialize_fq_from_hex(&hex.imaginary)?;
    Ok(Fq2::new(real, imaginary))
}
