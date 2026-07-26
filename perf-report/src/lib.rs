//! Formatting and publishing of zkVM performance reports.
//!
//! Two parts: a formatter that renders per-zkVM
//! [`ExecutionSummary`](zkaleido::ExecutionSummary) results as a report,
//! optionally with per-program deltas against a baseline recovered from the
//! last merged PR, and a GitHub poster that publishes it as a "sticky"
//! comment on a PR: the first post creates the comment, subsequent posts
//! update it in place.

mod args;
mod diff;
mod format;
mod github;
mod payload;
mod report;

pub use args::GithubReportArgs;
pub use format::{format_results, render_report};
pub use github::{
    BaselineReport, DEFAULT_API_BASE_URL, DEFAULT_BASELINE_COMMIT_LOOKBACK, DEFAULT_USER_AGENT,
    GithubPrReporter, GithubPrReporterConfig,
};
pub use payload::{ProgramPayload, ReportPayload, ZkVmPayload};
pub use report::{ProgramResult, ZkVmResults};
