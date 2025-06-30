use serde::{Deserialize, Serialize};

use crate::{g1::SAffineG1, g2::SAffineG2};

/// Proof for the Groth16 verification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Groth16Proof {
    pub(crate) ar: SAffineG1,
    pub(crate) krs: SAffineG1,
    pub(crate) bs: SAffineG2,
}
