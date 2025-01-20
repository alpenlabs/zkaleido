mod programs;

#[cfg(feature = "risc0")]
pub use programs::{fibonacci::risc0_fib_report, sha2::risc0_sha_report};
#[cfg(feature = "sp1")]
pub use programs::{fibonacci::sp1_fib_report, sha2::sp1_sha_report};
