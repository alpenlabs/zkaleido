use sha2::{Digest, Sha256};

/// Hashes the public inputs in the same format as the Plonk and Groth16 verifiers,
/// using the provided hash function.
pub(crate) fn hash_public_inputs_with_fn<F>(public_inputs: &[u8], hasher: F) -> [u8; 32]
where
    F: Fn(&[u8]) -> [u8; 32],
{
    let mut result = hasher(public_inputs);

    // The Plonk and Groth16 verifiers operate over a 254 bit field, so we need to zero
    // out the first 3 bits. The same logic happens in the SP1 Ethereum verifier contract.
    result[0] &= 0x1F;

    result
}

/// Hashes the public input using `Sha256`.
pub(crate) fn sha256_hash(inputs: &[u8]) -> [u8; 32] {
    Sha256::digest(inputs).into()
}

/// Hash the input using `Blake3`.
pub(crate) fn blake3_hash(inputs: &[u8]) -> [u8; 32] {
    *blake3::hash(inputs).as_bytes()
}
