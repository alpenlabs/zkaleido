use serde::{Deserialize, Serialize};

use crate::{g1::SAffineG1, g2::SAffineG2};

/// G1 elements of the Groth16 verifying key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Groth16G1 {
    /// The `α·G1` element in the G1 group.
    pub alpha: SAffineG1,

    /// The public-input commitments in G1, one for each instance.
    pub k: Vec<SAffineG1>,
}

/// G2 elements of the Groth16 verifying key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Groth16G2 {
    /// The `β·G2` element in the G2 group.
    pub beta: SAffineG2,

    /// The `δ·G2` element in the G2 group.
    pub delta: SAffineG2,

    /// The `γ·G2` element in the G2 group.
    pub gamma: SAffineG2,
}

/// Verification key for the Groth16 proof.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Groth16VerifyingKey {
    /// All G1-related verifying key elements.
    pub g1: Groth16G1,
    /// All G2-related verifying key elements.
    pub g2: Groth16G2,
}
