pub mod args;
pub mod programs;

use args::EvalArgs;
use clap::Parser;
use zkaleido::ZkVm;
use zkaleido_perf_report::{ZkVmResults, render_report};

const COMMENT_MARKER: &str = "zkaleido-perf-report";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sp1_sdk::utils::setup_logger();
    let args = EvalArgs::parse();

    let mut results: Vec<ZkVmResults> = Vec::new();

    #[cfg(feature = "sp1")]
    {
        let sp1_reports = programs::run_sp1_programs(&args.programs).await;
        results.push(ZkVmResults::new(ZkVm::SP1, sp1_reports));
    }

    #[cfg(feature = "risc0")]
    {
        let risc0_reports = programs::run_risc0_programs(&args.programs).await;
        results.push(ZkVmResults::new(ZkVm::Risc0, risc0_reports));
    }

    // Print results
    println!("{}", render_report(&results));

    // Post to GitHub PR
    if let Some(github) = &args.github {
        github
            .reporter(COMMENT_MARKER)
            .post_report(&results)
            .await?;
    }

    Ok(())
}
