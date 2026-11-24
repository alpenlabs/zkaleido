//! zkVM-compatible logging macros for ASM crates.
//!
//! This crate provides logging macros that work in both regular and zkVM environments:
//! - In regular builds: Uses the real `tracing` crate for full logging functionality
//! - In zkVM builds: Provides zero-cost no-op macros that validate format strings at compile time
//!
//! The span macros (`info_span!` and friends), [`Span`], and its guards follow the same split. In
//! zkVM builds a span is an empty value, so its fields are never evaluated.

#[cfg(target_os = "zkvm")]
mod noop;
#[cfg(target_os = "zkvm")]
pub use noop::{Entered, EnteredSpan, Span};
// When NOT building for zkVM, use real tracing macros
#[cfg(not(target_os = "zkvm"))]
pub use tracing::{
    Span, debug, debug_span, error, error_span, info, info_span,
    span::{Entered, EnteredSpan},
    trace, trace_span, warn, warn_span,
};
