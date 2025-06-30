//! A thin newtype wrapper around the [`substrate-bn`] crate’s types,
//! providing:
//!
//! - **Custom `Debug`** and `Display` implementations for human-friendly logging.
//! - **Serde `Serialize`/`Deserialize`** support (as hex strings).

mod error;
mod g1;
mod g2;
mod proof;
mod utils;
mod vk;

pub use g1::SAffineG1;
pub use g2::SAffineG2;
pub use proof::Groth16Proof;
pub use vk::{Groth16G1, Groth16G2, Groth16VerifyingKey};
