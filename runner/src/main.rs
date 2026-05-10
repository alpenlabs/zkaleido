pub mod args;
pub mod format;
pub mod github;
pub mod programs;

use anyhow::Result;
use args::EvalArgs;
use clap::Parser;
use format::{format_header, format_results};
use github::{format_github_message, post_to_github_pr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sp1_sdk::utils::setup_logger();
    let args = EvalArgs::parse();

    let mut results_text = vec![format_header(&args)];

    #[cfg(feature = "sp1")]
    {
        let sp1_reports = programs::run_sp1_programs(&args.programs).await;
        results_text.push(format_results(&sp1_reports, "SP1".to_owned()));
    }

    #[cfg(feature = "risc0")]
    {
        let risc0_reports = programs::run_risc0_programs(&args.programs).await;
        results_text.push(format_results(&risc0_reports, "RISC0".to_owned()));
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
