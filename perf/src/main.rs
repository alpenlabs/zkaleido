use anyhow::Result;
use clap::{command, Parser};
use num_format::{Locale, ToFormattedString};
use reqwest::Client;
use serde::Serialize;
use serde_json::json;
use strata_zkvm::ProofReport;
pub use zkvm_runner::{risc0_fib_report, risc0_sha_report, sp1_fib_report, sp1_sha_report};

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

/// Flags for CLI invocation being parsed.
#[derive(Parser, Clone)]
#[command(about = "Evaluate the performance of SP1 on programs.")]
struct EvalArgs {
    /// Whether to post on github or run locally and only log the results.
    #[arg(long, default_value_t = false)]
    pub post_to_gh: bool,

    /// The GitHub token for authentication.
    #[arg(long, default_value = "")]
    pub github_token: String,

    /// The GitHub PR number.
    #[arg(long, default_value = "")]
    pub pr_number: String,

    /// The commit hash.
    #[arg(long, default_value = "local_commit")]
    pub commit_hash: String,
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
    let mut reports = vec![];

    reports.push(sp1_fib_report().into());
    reports.push(sp1_sha_report().into());

    reports
}

/// Runs SP1 programs to generate reports.
///
/// Generates [`PerformanceReport`] for each invocation.
fn run_risc0_programs() -> Vec<PerformanceReport> {
    let mut reports = vec![];

    reports.push(risc0_fib_report().into());
    reports.push(risc0_sha_report().into());

    reports
}

/// Returns a formatted header for the performance report with basic PR data.
fn format_header(args: &EvalArgs) -> String {
    let mut detail_text = String::new();

    if args.post_to_gh {
        detail_text.push_str(&format!("*Commit*: {}\n", &args.commit_hash[..8]));
    } else {
        detail_text.push_str("*Local execution*\n");
    }

    detail_text
}

/// Returns formatted results for the [`PerformanceReport`]s shaped in a table.
fn format_results(results: &[PerformanceReport], host_name: String) -> String {
    let mut table_text = String::new();
    table_text.push('\n');
    table_text.push_str("| program           | cycles      | success  |\n");
    table_text.push_str("|-------------------|-------------|----------|");

    for result in results.iter() {
        table_text.push_str(&format!(
            "\n| {:<17} | {:>11} | {:<7} |",
            result.program,
            result.cycles.to_formatted_string(&Locale::en),
            if result.success { "✅" } else { "❌" }
        ));
    }
    table_text.push('\n');

    format!("*{} Performance Test Results*\n {}", host_name, table_text)
}

/// Posts the message to the PR on the github.
///
/// Updates an existing previous comment (if there is one) or posts a new comment.
async fn post_to_github_pr(
    args: &EvalArgs,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    // Get all comments on the PR
    const BASE_URL: &str = "https://api.github.com/repos/alpenlabs/strata";
    let comments_url = format!("{}/issues/{}/comments", BASE_URL, &args.pr_number);
    let comments_response = client
        .get(&comments_url)
        .header("Authorization", format!("Bearer {}", &args.github_token))
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "strata-perf-bot")
        .send()
        .await?;

    let comments: Vec<serde_json::Value> = comments_response.json().await?;

    // Look for an existing comment from our bot
    let bot_comment = comments.iter().find(|comment| {
        comment["user"]["login"]
            .as_str()
            .map(|login| login == "github-actions[bot]")
            .unwrap_or(false)
    });

    if let Some(existing_comment) = bot_comment {
        // Update the existing comment
        let comment_url = existing_comment["url"].as_str().unwrap();
        let response = client
            .patch(comment_url)
            .header("Authorization", format!("Bearer {}", &args.github_token))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "strata-perf-bot")
            .json(&json!({
                "body": message
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to update comment: {:?}", response.text().await?).into());
        }
    } else {
        // Create a new comment
        let response = client
            .post(&comments_url)
            .header("Authorization", format!("Bearer {}", &args.github_token))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "strata-perf-bot")
            .json(&json!({
                "body": message
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to post comment: {:?}", response.text().await?).into());
        }
    }

    Ok(())
}

fn format_github_message(results_text: &[String]) -> String {
    let mut formatted_message = String::new();

    for line in results_text {
        formatted_message.push_str(&line.replace('*', "**"));
        formatted_message.push('\n');
    }

    formatted_message
}
