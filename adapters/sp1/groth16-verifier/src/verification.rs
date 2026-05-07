use bn::{Fr, G1, G2, Gt, pairing_batch};

use crate::{
    error::Sp1Groth16Error,
    types::{proof::Groth16Proof, vk::Groth16VerifyingKey},
};

/// Verify an SP1 Groth16 proof using algebraic public inputs.
pub fn verify_sp1_groth16_algebraic(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[Fr],
) -> Result<(), Sp1Groth16Error> {
    let prepared_input = public_inputs.iter().zip(vk.g1.k.iter().skip(1)).fold(
        Into::<G1>::into(vk.g1.k[0]),
        |acc, (input, k)| {
            // A zero public input contributes 0 to the prepared point, so the scalar
            // multiplication and addition can be skipped.
            if *input == Fr::zero() {
                acc
            } else {
                acc + Into::<G1>::into(*k) * *input
            }
        },
    );

    if pairing_batch(&[
        (-Into::<G1>::into(proof.ar), proof.bs.into()),
        (prepared_input, vk.g2.gamma.into()),
        (proof.krs.into(), vk.g2.delta.into()),
        (vk.g1.alpha.into(), -Into::<G2>::into(vk.g2.beta)),
    ]) == Gt::one()
    {
        Ok(())
    } else {
        Err(Sp1Groth16Error::VerificationFailed)
    }
}
