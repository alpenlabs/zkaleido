use bn::{AffineG1, AffineG2};

/// G1 elements of the verification key.
#[derive(Clone, PartialEq)]
pub(crate) struct Groth16G1 {
    pub(crate) alpha: AffineG1,
    pub(crate) k: Vec<AffineG1>,
}

/// G2 elements of the verification key.
#[derive(Clone, PartialEq)]
pub(crate) struct Groth16G2 {
    pub(crate) beta: AffineG2,
    pub(crate) delta: AffineG2,
    pub(crate) gamma: AffineG2,
}

/// Verification key for the Groth16 proof.
#[derive(Clone, PartialEq)]
pub(crate) struct Groth16VerifyingKey {
    pub(crate) g1: Groth16G1,
    pub(crate) g2: Groth16G2,
}

/// Proof for the Groth16 verification.
pub(crate) struct Groth16Proof {
    pub(crate) ar: AffineG1,
    pub(crate) krs: AffineG1,
    pub(crate) bs: AffineG2,
}
