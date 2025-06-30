use serde::{Deserialize, Serialize};

use crate::{g1::SAffineG1, g2::SAffineG2};

/// Proof for the Groth16 verification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Groth16Proof {
    pub ar: SAffineG1,
    pub krs: SAffineG1,
    pub bs: SAffineG2,
}
