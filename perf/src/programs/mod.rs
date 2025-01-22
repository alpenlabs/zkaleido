#[cfg(feature = "fibonacci")]
mod fibonacci;
#[cfg(feature = "schnorr-sig-verify")]
mod schnorr;
#[cfg(feature = "sha2-chain")]
mod sha2;

use crate::PerformanceReport;

/// Runs SP1 programs to generate reports.
///
/// Generates [`PerformanceReport`] for each invocation.
#[cfg(feature = "sp1")]
pub fn run_sp1_programs() -> Vec<PerformanceReport> {
    vec![
        #[cfg(feature = "fibonacci")]
        fibonacci::sp1_fib_report().into(),
        #[cfg(feature = "sha2-chain")]
        sha2::sp1_sha_report().into(),
        #[cfg(feature = "schnorr-sig-verify")]
        schnorr::sp1_schnorr_sig_verify_report().into(),
    ]
}

/// Runs Risc0 programs to generate reports.
///
/// Generates [`PerformanceReport`] for each invocation.
#[cfg(feature = "risc0")]
pub fn run_risc0_programs() -> Vec<PerformanceReport> {
    vec![
        #[cfg(feature = "fibonacci")]
        fibonacci::risc0_fib_report().into(),
        #[cfg(feature = "sha2-chain")]
        sha2::risc0_sha_report().into(),
        #[cfg(feature = "schnorr-sig-verify")]
        schnorr::risc0_schnorr_sig_verify_report().into(),
    ]
}
