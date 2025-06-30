use serde::{Deserialize, Serialize};

use crate::{g1::SAffineG1, g2::SAffineG2};

/// G1 elements of the verification key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Groth16G1 {
    pub alpha: SAffineG1,
    pub k: Vec<SAffineG1>,
}

/// G2 elements of the verification key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Groth16G2 {
    pub beta: SAffineG2,
    pub delta: SAffineG2,
    pub gamma: SAffineG2,
}

/// Verification key for the Groth16 proof.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Groth16VerifyingKey {
    pub g1: Groth16G1,
    pub g2: Groth16G2,
}
