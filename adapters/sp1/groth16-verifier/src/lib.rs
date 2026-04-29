//! # zkaleido-sp1-groth16-verifier
//!
//! SP1 Groth16 proof verification for zkaleido.
//!
//! [`SP1Groth16Verifier`] is the crate's entry point. Its operational model is
//! **load once, verify many**: [`SP1Groth16Verifier::load`] parses the GNARK-compressed
//! verifying key, pins the constants the verifier is willing to accept, and pre-processes
//! the VK so that each subsequent [`SP1Groth16Verifier::verify`] call only handles the
//! statement-specific public inputs.
//!
//! # What lives where
//!
//! - [`SP1Groth16Verifier`] — the public entry point and its [`zkaleido::ZkVmVerifier`]
//!   adapter.
//! - [`ParsedSp1Groth16Proof`] — on-wire byte format and parsing of the optional prefix
//!   fields (see its docs for the exact layout and which prefix fields may be omitted).
//! - [`verify_sp1_groth16_algebraic`] — the pure algebraic pairing check, separated out
//!   so it can be reused without the SP1-specific cross-checks.
//! - [`crate::hashes`] — hashing `public_values` to a BN254 `Fr` element (SHA-256 and
//!   Blake3, both accepted by SP1's circuit).
//!
//! # The "fold fixed inputs into K0" optimisation
//!
//! SP1's Groth16 circuit takes
//! `(program_vk_hash, hash(public_values), exit_code, vk_root, proof_nonce)` as public
//! inputs. Two of those — `program_vk_hash` and `vk_root` — are constant for a given
//! verifier instance, so [`SP1Groth16Verifier::load`] folds them into `K0` once at load
//! time and removes the corresponding `K1` and `K4` from the dynamic input basis. This
//! drops the per-verify scalar multiplications from five to three and shrinks the stored
//! VK. SP1 versions before v6 do not expose `vk_root` as a public input, so only the
//! `program_vk_hash` fold applies there.
//!
//! # Trust boundaries enforced by [`SP1Groth16Verifier::verify`]
//!
//! 1. **Prefix cross-check.** The proof's optional `vk_hash_tag` and `vk_root` prefix
//!    fields, when present, must equal the values pinned on the verifier; when absent,
//!    the call falls through to the algebraic check, which still binds the proof to the
//!    loaded VK.
//! 2. **Exit-code policy.** Governed by `require_success` on [`SP1Groth16Verifier`] —
//!    see that field's doc for the full `require_success × proof.exit_code` matrix.

#[cfg(all(test, not(feature = "serde")))]
use bincode as _;
#[cfg(all(test, not(feature = "serde")))]
use serde_json as _;

#[cfg(feature = "borsh")]
mod borsh;
mod error;
pub mod hashes;
#[cfg(feature = "serde")]
mod serde;
mod types;
mod verification;
mod verifier;

pub use types::{
    constant::{
        GROTH16_PROOF_COMPRESSED_SIZE, GROTH16_PROOF_UNCOMPRESSED_SIZE,
        SP1_GROTH16_VK_COMPRESSED_SIZE_MERGED, SP1_GROTH16_VK_UNCOMPRESSED_SIZE_MERGED,
        VK_HASH_PREFIX_LENGTH,
    },
    parsed_proof::ParsedSp1Groth16Proof,
    proof::Groth16Proof,
    vk::Groth16VerifyingKey,
};
pub use verification::verify_sp1_groth16_algebraic;
pub use verifier::SP1Groth16Verifier;
