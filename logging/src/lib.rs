//! zkVM-compatible logging macros for ASM crates.
//!
//! This crate provides logging macros that work in both regular and zkVM environments:
//! - In regular builds: Uses the real `tracing` crate for full logging functionality
//! - In zkVM builds: Provides zero-cost no-op macros that validate format strings at compile time

#[cfg(target_os = "zkvm")]
mod noop;
// When NOT building for zkVM, use real tracing macros
#[cfg(not(target_os = "zkvm"))]
pub use tracing::{debug, error, info, trace, warn};
