use bn::{pairing_batch, Fr, Gt, G1, G2};

use crate::{
    conversion::{load_groth16_proof_from_bytes, load_groth16_verifying_key_from_bytes},
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
        .fold(G1::from(vk.g1.k[0]), |acc, (i, b)| {
            acc + (G1::from(*b) * (*i))
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

/// Verifies a Gnark Groth16 proof using raw byte inputs.
///
/// WARNING: if you're verifying an SP1 proof, you should use [`verify`] instead.
/// This is a lower-level verification method that works directly with raw bytes rather than
/// the SP1 SDK's data structures.
///
/// # Arguments
///
/// * `proof` - The raw Groth16 proof bytes (without the 4-byte vkey hash prefix)
/// * `public_inputs` - The public inputs to the circuit
/// * `groth16_vk` - The Groth16 verifying key bytes
///
/// # Returns
///
/// A [`Result`] containing unit `()` if the proof is valid,
/// or a [`Groth16Error`] if verification fails.
///
/// # Note
///
/// This method expects the raw proof bytes without the 4-byte vkey hash prefix that
/// [`verify`] checks. If you have a complete proof with the prefix, use [`verify`] instead.
pub fn verify_gnark_proof(
    proof: &[u8],
    public_inputs: &[[u8; 32]],
    groth16_vk: &[u8],
) -> Result<(), Groth16Error> {
    let proof = load_groth16_proof_from_bytes(proof)?;
    let groth16_vk = load_groth16_verifying_key_from_bytes(groth16_vk)?;

    let public_inputs = public_inputs
        .iter()
        .map(|input| Fr::from_slice(input).unwrap())
        .collect::<Vec<_>>();
    verify_groth16_algebraic(&groth16_vk, &proof, &public_inputs)
}
