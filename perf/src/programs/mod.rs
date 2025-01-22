#[cfg(feature = "fibonacci")]
mod fibonacci;
#[cfg(feature = "schnorr-sig-verify")]
mod schnorr;
#[cfg(feature = "sha2-chain")]
mod sha2;

#[cfg(feature = "fibonacci")]
use fibonacci::{risc0_fib_report, sp1_fib_report};
#[cfg(feature = "schnorr-sig-verify")]
use schnorr::{risc0_schnorr_sig_verify_report, sp1_schnorr_sig_verify_report};
#[cfg(feature = "sha2-chain")]
use sha2::{risc0_sha_report, sp1_sha_report};

use crate::PerformanceReport;

/// Runs SP1 programs to generate reports.
///
/// Generates [`PerformanceReport`] for each invocation.
pub fn run_sp1_programs() -> Vec<PerformanceReport> {
    vec![
        #[cfg(feature = "fibonacci")]
        sp1_fib_report().into(),
        #[cfg(feature = "sha2-chain")]
        sp1_sha_report().into(),
        #[cfg(feature = "schnorr-sig-verify")]
        sp1_schnorr_sig_verify_report().into(),
    ]
}

/// Runs Risc0 programs to generate reports.
///
/// Generates [`PerformanceReport`] for each invocation.
pub fn run_risc0_programs() -> Vec<PerformanceReport> {
    vec![
        #[cfg(feature = "fibonacci")]
        risc0_fib_report().into(),
        #[cfg(feature = "sha2-chain")]
        risc0_sha_report().into(),
        #[cfg(feature = "schnorr-sig-verify")]
        risc0_schnorr_sig_verify_report().into(),
    ]
}
