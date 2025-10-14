use bn::{pairing_batch, Fr, Gt, G1, G2};

use crate::{
    error::Groth16Error,
    types::{proof::Groth16Proof, vk::Groth16VerifyingKey},
};

/// Verify SP1 Groth16 proof using algebraic inputs.
///
/// First, prepare the public inputs by folding them with the verification key.
/// Then, verify the proof by checking the pairing equation.
pub fn verify_sp1_groth16_algebraic(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_parameters_hash: &Fr,
) -> Result<(), Groth16Error> {
    let k0_prime: G1 = vk.g1.k[0].into();
    let k1: G1 = vk.g1.k[1].into();
    let prepared_input = k0_prime + k1 * *public_parameters_hash;

    if pairing_batch(&[
        (-Into::<G1>::into(proof.ar), proof.bs.into()),
        (prepared_input, vk.g2.gamma.into()),
        (proof.krs.into(), vk.g2.delta.into()),
        (vk.g1.alpha.into(), -Into::<G2>::into(vk.g2.beta)),
    ]) == Gt::one()
    {
        Ok(())
    } else {
        Err(Groth16Error::VerificationFailed)
    }
}
