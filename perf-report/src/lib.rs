//! Formatting and publishing of zkVM performance reports.
//!
//! Two parts: a formatter that renders per-zkVM
//! [`ExecutionSummary`](zkaleido::ExecutionSummary) results as a report, and
//! a GitHub poster that publishes it as a "sticky" comment on a PR: the
//! first post creates the comment, subsequent posts update it in place.

mod args;
mod format;
mod github;
mod payload;
mod report;

pub use args::GithubReportArgs;
pub use format::{format_results, render_report};
pub use github::{
    DEFAULT_API_BASE_URL, DEFAULT_USER_AGENT, GithubPrReporter, GithubPrReporterConfig,
};
pub use payload::{ProgramPayload, ReportPayload, ZkVmPayload};
pub use report::{ProgramResult, ZkVmResults};
