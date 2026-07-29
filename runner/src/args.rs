use clap::Parser;
use zkaleido_perf_report::GithubReportArgs;

use crate::programs::GuestProgram;

/// Flags for CLI invocation being parsed.
#[derive(Parser, Clone)]
#[command(about = "Evaluate the performance of SP1 on programs.")]
pub struct EvalArgs {
    /// GitHub reporting options; the report is posted to the PR only when
    /// at least one of these is provided.
    #[command(flatten)]
    pub github: Option<GithubReportArgs>,

    /// Programs to run (comma-delimited).
    /// e.g. `--programs fibonacci,sha2-chain,schnorr-sig-verify`
    #[arg(long, value_enum, value_delimiter = ',')]
    pub programs: Vec<GuestProgram>,
}
