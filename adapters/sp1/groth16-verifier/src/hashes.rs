//! Hash functions for SP1 Groth16 proof verification.
//!
//! This module provides hash functions for processing public inputs in a format
//! compatible with Groth16 verifier. SP1 supports both SHA-256 and Blake3
//! hash functions for public input processing.

use bn::Fr;
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Hashes the input using SHA-256.
fn sha256(inputs: &[u8]) -> [u8; 32] {
    Sha256::digest(inputs).into()
}

/// Hashes the input using Blake3.
fn blake3(inputs: &[u8]) -> [u8; 32] {
    *blake3::hash(inputs).as_bytes()
}

/// Hashes public inputs and converts to an Fr element for Groth16 verifiers.
///
/// This function applies the provided hash function, masks the result to fit within the
/// 254-bit BN254 field by zeroing the top 3 bits, and converts to an Fr element.
///
/// # Parameters
/// - `public_inputs`: The raw public input bytes to hash
/// - `hasher`: Hash function that takes bytes and returns a 32-byte digest
///
/// # Returns
/// An Fr element suitable for circuit verification, or an error if the conversion fails
///
/// # Note
/// The top 3 bits are zeroed (masked with 0x1F) to ensure the 256-bit hash fits within
/// the 254-bit BN254 scalar field, matching the behavior in SP1's Ethereum verifier contract.
fn hash_public_inputs<F>(public_inputs: &[u8], hasher: F) -> Result<Fr, Error>
where
    F: Fn(&[u8]) -> [u8; 32],
{
    let mut result = hasher(public_inputs);

    // Groth16 verifiers operate over a 254-bit field, so we need to zero
    // out the first 3 bits. The same logic happens in the SP1 Ethereum verifier contract.
    result[0] &= 0x1F;

    Fr::from_slice(&result).map_err(|_| Error::FailedToGetFrFromRandomBytes)
}

/// Hashes public inputs using SHA-256 and converts the result to an Fr element.
///
/// This is a convenience function that uses SHA-256 for hashing public inputs
/// with proper field masking for circuit verification.
pub fn sha256_to_fr(public_inputs: &[u8]) -> Result<Fr, Error> {
    hash_public_inputs(public_inputs, sha256)
}

/// Hashes public inputs using Blake3 and converts the result to an Fr element.
///
/// This is a convenience function that uses Blake3 for hashing public inputs
/// with proper field masking for circuit verification.
pub fn blake3_to_fr(public_inputs: &[u8]) -> Result<Fr, Error> {
    hash_public_inputs(public_inputs, blake3)
}
