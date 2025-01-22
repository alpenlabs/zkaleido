pub mod args;
pub mod format;
pub mod github;

use anyhow::Result;
use args::EvalArgs;
use clap::Parser;
use format::{format_header, format_results};
use github::{format_github_message, post_to_github_pr};
use serde::Serialize;
use strata_zkvm::ProofReport;
pub use zkvm_runner::{risc0_fib_report, risc0_sha_report, sp1_fib_report, sp1_sha_report};
use zkvm_runner::{risc0_schnorr_sig_verify_report, sp1_schnorr_sig_verify_report};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sp1_sdk::utils::setup_logger();
    let args = EvalArgs::parse();

    let mut results_text = vec![format_header(&args)];

    let sp1_reports = run_sp1_programs();
    results_text.push(format_results(&sp1_reports, "SP1".to_owned()));

    let risc0_reports = run_risc0_programs();
    results_text.push(format_results(&risc0_reports, "RISC0".to_owned()));

    // Print results
    println!("{}", results_text.join("\n"));

    if args.post_to_gh {
        // Post to GitHub PR
        let message = format_github_message(&results_text);
        post_to_github_pr(&args, &message).await?;
    }

    if !sp1_reports.iter().all(|r| r.success) {
        println!("Some programs failed. Please check the results above.");
        std::process::exit(1);
    }

    Ok(())
}

/// Basic data about the performance of a certain prover program.
///
/// TODO: Currently, only program and cycles are used, populalate the rest
/// as part of full execution with timings reporting.
#[derive(Debug, Serialize)]
pub struct PerformanceReport {
    program: String,
    cycles: u64,
    success: bool,
}

impl From<ProofReport> for PerformanceReport {
    fn from(value: ProofReport) -> Self {
        PerformanceReport {
            program: value.report_name,
            cycles: value.cycles,
            success: true,
        }
    }
}

/// Runs SP1 programs to generate reports.
///
/// Generates [`PerformanceReport`] for each invocation.
fn run_sp1_programs() -> Vec<PerformanceReport> {
    vec![
        sp1_fib_report().into(),
        sp1_sha_report().into(),
        sp1_schnorr_sig_verify_report().into(),
    ]
}

/// Runs Risc0 programs to generate reports.
///
/// Generates [`PerformanceReport`] for each invocation.
fn run_risc0_programs() -> Vec<PerformanceReport> {
    vec![
        risc0_fib_report().into(),
        risc0_sha_report().into(),
        risc0_schnorr_sig_verify_report().into(),
    ]
}
