use clap::{command, Parser};

/// Flags for CLI invocation being parsed.
#[derive(Parser, Clone)]
#[command(about = "Evaluate the performance of SP1 on programs.")]
pub struct EvalArgs {
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
