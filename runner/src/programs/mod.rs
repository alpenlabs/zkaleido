use std::str::FromStr;

use clap::ValueEnum;
use zkaleido::ExecutionSummary;

mod fibonacci;
mod fibonacci_composition;
mod groth16_verify_sp1;
mod schnorr;
mod sha2;

#[derive(Debug, Clone, ValueEnum)]
#[non_exhaustive]
pub enum GuestProgram {
    Fibonacci,
    FibonacciComposition,
    Sha2Chain,
    SchnorrSigVerify,
    Groth16VerifySP1,
}

impl FromStr for GuestProgram {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "fibonacci" => Ok(GuestProgram::Fibonacci),
            "fibonacci-composition" => Ok(GuestProgram::FibonacciComposition),
            "sha2-chain" => Ok(GuestProgram::Sha2Chain),
            "schnorr-sig-verify" => Ok(GuestProgram::SchnorrSigVerify),
            "groth16-verify-sp1" => Ok(GuestProgram::Groth16VerifySP1),
            // Add more matches
            _ => Err(format!("unknown program: {}", s)),
        }
    }
}

/// Runs SP1 programs to generate reports.
///
/// Pairs each program's [`ZkVmProgram::name`] with its [`ExecutionSummary`].
#[cfg(feature = "sp1")]
pub async fn run_sp1_programs(programs: &[GuestProgram]) -> Vec<(String, ExecutionSummary)> {
    let mut reports = Vec::with_capacity(programs.len());
    for program in programs {
        let report = match program {
            GuestProgram::Fibonacci => fibonacci::sp1_fib_report().await,
            GuestProgram::FibonacciComposition => {
                fibonacci_composition::sp1_fib_composition_report().await
            }
            GuestProgram::Sha2Chain => sha2::sp1_sha_report().await,
            GuestProgram::SchnorrSigVerify => schnorr::sp1_schnorr_sig_verify_report().await,
            GuestProgram::Groth16VerifySP1 => groth16_verify_sp1::sp1_groth16_verify().await,
        };
        reports.push(report);
    }
    reports
}

/// Runs Risc0 programs to generate reports.
///
/// Pairs each program's [`ZkVmProgram::name`] with its [`ExecutionSummary`].
#[cfg(feature = "risc0")]
pub async fn run_risc0_programs(programs: &[GuestProgram]) -> Vec<(String, ExecutionSummary)> {
    let mut reports = Vec::with_capacity(programs.len());
    for program in programs {
        let report = match program {
            GuestProgram::Fibonacci => fibonacci::risc0_fib_report().await,
            GuestProgram::FibonacciComposition => {
                fibonacci_composition::risc0_fib_composition_report().await
            }
            GuestProgram::Sha2Chain => sha2::risc0_sha_report().await,
            GuestProgram::SchnorrSigVerify => schnorr::risc0_schnorr_sig_verify_report().await,
            GuestProgram::Groth16VerifySP1 => groth16_verify_sp1::risc0_groth16_verify().await,
        };
        reports.push(report);
    }
    reports
}
