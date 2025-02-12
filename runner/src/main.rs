pub mod args;
pub mod format;
pub mod github;
pub mod programs;

use anyhow::Result;
use args::EvalArgs;
use clap::Parser;
use format::{format_header, format_results};
use github::{format_github_message, post_to_github_pr};
use serde::Serialize;
use zkaleido::ProofReport;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sp1_sdk::utils::setup_logger();
    let args = EvalArgs::parse();

    let mut results_text = vec![format_header(&args)];

    #[cfg(feature = "sp1")]
    {
        let sp1_reports = programs::run_sp1_programs(&args.programs);
        results_text.push(format_results(&sp1_reports, "SP1".to_owned()));
        if !sp1_reports.iter().all(|r| r.success) {
            println!("Some SP1 programs failed. Please check the results below.");
            std::process::exit(1);
        }
    }

    #[cfg(feature = "risc0")]
    {
        let risc0_reports = programs::run_risc0_programs(&args.programs);
        results_text.push(format_results(&risc0_reports, "RISC0".to_owned()));
        if !risc0_reports.iter().all(|r| r.success) {
            println!("Some Risc0 programs failed. Please check the results below.");
            std::process::exit(1);
        }
    }

    // Print results
    println!("{}", results_text.join("\n"));

    if args.post_to_gh {
        // Post to GitHub PR
        let message = format_github_message(&results_text);
        post_to_github_pr(&args, &message).await?;
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
            program: value.name,
            cycles: value.cycles,
            success: true,
        }
    }
}
