use bn::{pairing_batch, Fr, Gt, G1, G2};

use crate::{
    error::Groth16Error,
    types::{Groth16Proof, Groth16VerifyingKey},
};

/// Prepare the inputs for the Groth16 verification by combining the public inputs with the
/// corresponding elements of the verification key.
fn prepare_inputs(vk: Groth16VerifyingKey, public_inputs: &[Fr]) -> Result<G1, Groth16Error> {
    if (public_inputs.len() + 1) != vk.g1.k.len() {
        return Err(Groth16Error::PrepareInputsFailed);
    }
    Ok(public_inputs
        .iter()
        .zip(vk.g1.k.iter().skip(1))
        .fold(vk.g1.k[0].into(), |acc, (i, b)| {
            let b: G1 = (*b).into();
            acc + (b * *i)
        }))
}

/// Verify the Groth16 proof using algebraic inputs.
///
/// First, prepare the public inputs by folding them with the verification key.
/// Then, verify the proof by checking the pairing equation.
pub(crate) fn verify_groth16_algebraic(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[Fr],
) -> Result<(), Groth16Error> {
    let prepared_inputs = prepare_inputs(vk.clone(), public_inputs)?;

    if pairing_batch(&[
        (-Into::<G1>::into(proof.ar), proof.bs.into()),
        (prepared_inputs, vk.g2.gamma.into()),
        (proof.krs.into(), vk.g2.delta.into()),
        (vk.g1.alpha.into(), -Into::<G2>::into(vk.g2.beta)),
    ]) == Gt::one()
    {
        Ok(())
    } else {
        Err(Groth16Error::ProofVerificationFailed)
    }
}
