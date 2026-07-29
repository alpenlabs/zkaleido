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

    // Resolve the reporting target up front so a misconfiguration fails
    // before the benchmarks run, not after.
    let reporter = args
        .github
        .as_ref()
        .map(|github| github.reporter(COMMENT_MARKER))
        .transpose()?;

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

    // A missing baseline only degrades the report to absolute numbers, so
    // fetch failures must not block posting it, but the reported header
    // should still say the lookup failed rather than implying a clean miss.
    let mut baseline_lookup_failed = false;
    let baseline = match &reporter {
        Some(reporter) => match reporter.fetch_baseline().await {
            Ok(baseline) => baseline,
            Err(err) => {
                eprintln!("warning: failed to fetch baseline report: {err:#}");
                baseline_lookup_failed = true;
                None
            }
        },
        None => None,
    };

    // Print results
    println!(
        "{}",
        render_report(
            &results,
            baseline.as_ref().map(|baseline| &baseline.payload)
        )
    );

    // Post to GitHub PR
    if let Some(reporter) = reporter {
        reporter
            .post_report(&results, baseline.as_ref(), baseline_lookup_failed)
            .await?;
    }

    Ok(())
}
