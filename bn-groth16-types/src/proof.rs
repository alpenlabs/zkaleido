use serde::{Deserialize, Serialize};

use crate::{g1::SAffineG1, g2::SAffineG2};

/// Proof for the Groth16 verification.
/// ///
/// This struct holds the three affine group elements that the verifier
/// checks when verifying a Groth16 proof:
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Groth16Proof {
    /// The `A·r` element in the `G1` group.
    pub ar: SAffineG1,
    /// The `K_{rs}` element in the `G1` group,
    /// encoding the combined randomness proofs.
    pub krs: SAffineG1,
    /// The `B·s` element in the `G2` group.
    pub bs: SAffineG2,
}
