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
//! - [`SP1Groth16Verifier`] — the public entry point and its [`zkaleido::ZkVmVerifier`] adapter.
//! - [`Sp1Groth16Proof`] — on-wire byte format and parsing of the optional prefix fields (see its
//!   docs for the exact layout and which prefix fields may be omitted).
//! - [`verify_sp1_groth16_algebraic`] — the pure algebraic pairing check, separated out so it can
//!   be reused without the SP1-specific cross-checks.
//! - [`crate::hashes`] — hashing `public_values` to a BN254 `Fr` element (SHA-256 and Blake3, both
//!   accepted by SP1's circuit).
//!
//! # The "fold fixed inputs into K0" optimisation
//!
//! SP1's Groth16 circuit takes
//! `(program_vk_hash, hash(public_values), exit_code, vk_root, proof_nonce)` as public
//! inputs. `program_vk_hash` is constant for a given verifier instance, so
//! [`SP1Groth16Verifier::load`] folds it into `K0` once at load time and removes `K1`
//! from the dynamic input basis. This drops the per-verify scalar multiplications from
//! five to four and shrinks the stored VK by one K point.
//!
//! # Trust boundaries enforced by [`SP1Groth16Verifier::verify`]
//!
//! 1. **Prefix cross-check.** The proof's optional `vk_hash_tag` and `vk_root` prefix fields, when
//!    present, must equal the values pinned on the verifier; when absent, the call falls through to
//!    the algebraic check, which still binds the proof to the loaded VK.
//! 2. **Exit-code policy.** Governed by `require_success` on [`SP1Groth16Verifier`] — see that
//!    field's doc for the full `require_success × proof.exit_code` matrix.
//!
//! # Backwards compatibility with SP1 v5
//!
//! [`SP1Groth16Verifier::verify`] always builds the v6-shaped public-input vector
//! `(program_vk_hash, hash(public_values), exit_code, vk_root, proof_nonce)`. v5 proofs,
//! whose circuit only committed to `(program_vk_hash, hash(public_values))`, still verify
//! under that vector when the v6 additions all default to zero on the v5 path:
//! `require_success` resolves a missing `exit_code` to `SUCCESS_EXIT_CODE` (`0`), the
//! verifier is loaded with the all-zero v5 `vk_root`, and a missing `proof_nonce` defaults
//! to zero. [`verify_sp1_groth16_algebraic`] short-circuits zero public inputs, so the
//! trailing K-basis terms drop out of the prepared point and the pairing reduces to
//! exactly the v5 check.

#[cfg(all(test, not(feature = "serde")))]
use bincode as _;
#[cfg(all(test, not(feature = "serde")))]
use serde_json as _;

#[cfg(feature = "borsh")]
mod borsh;
mod error;
pub mod hashes;
mod proof;
#[cfg(feature = "serde")]
mod serde;
mod types;
mod verification;
mod verifier;

pub use proof::Sp1Groth16Proof;
pub use types::{
    constant::{
        GROTH16_PROOF_COMPRESSED_SIZE, GROTH16_PROOF_UNCOMPRESSED_SIZE,
        SP1_GROTH16_VK_COMPRESSED_SIZE_MERGED, SP1_GROTH16_VK_UNCOMPRESSED_SIZE_MERGED,
        VK_HASH_PREFIX_LENGTH,
    },
    proof::Groth16Proof,
    vk::Groth16VerifyingKey,
};
pub use verification::verify_sp1_groth16_algebraic;
pub use verifier::SP1Groth16Verifier;
