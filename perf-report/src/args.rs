use std::{env, fmt};

use anyhow::{Context, Result};
use clap::Args;

use crate::github::{
    DEFAULT_API_BASE_URL, DEFAULT_BASELINE_COMMIT_LOOKBACK, GithubPrReporter,
    GithubPrReporterConfig,
};

/// Returns the PR number parsed from the `GITHUB_REF` env var set by GitHub
/// Actions (`refs/pull/<number>/merge` on pull_request-triggered runs),
/// empty on any other trigger or outside of CI.
fn default_pr_number() -> String {
    let Ok(github_ref) = env::var("GITHUB_REF") else {
        return String::new();
    };
    github_ref
        .strip_prefix("refs/pull/")
        .and_then(|rest| rest.split('/').next())
        .map(str::to_string)
        .unwrap_or_default()
}

/// Returns the repository from the `GITHUB_REPOSITORY` env var set by
/// GitHub Actions, empty outside of CI.
fn default_github_repo() -> String {
    env::var("GITHUB_REPOSITORY").unwrap_or_default()
}

/// Returns the commit hash from the `GITHUB_SHA` env var set by GitHub
/// Actions, empty outside of CI.
fn default_commit_hash() -> String {
    env::var("GITHUB_SHA").unwrap_or_default()
}

/// Returns the API base URL from the `GITHUB_API_URL` env var set by GitHub
/// Actions (which points at the enterprise host on GHES), falling back to
/// the public GitHub API outside of CI.
fn default_api_base_url() -> String {
    env::var("GITHUB_API_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
}

/// CLI arguments for posting a performance report to a GitHub PR.
///
/// Meant to be embedded in a binary's argument struct via
/// `#[command(flatten)]`, either directly or as `Option<GithubReportArgs>`
/// to make "was any reporting flag given" drive whether to post. All
/// defaults are computed (not clap `env` attributes) so that env vars alone
/// never count as the group being present.
#[derive(Args, Clone)]
pub struct GithubReportArgs {
    /// The GitHub token for authentication.
    #[arg(long, default_value = "")]
    pub github_token: String,

    /// The GitHub PR number to comment on.
    ///
    /// Defaults to the PR that triggered the CI run.
    #[arg(long, default_value_t = default_pr_number())]
    pub pr_number: String,

    /// GitHub repository in `owner/repo` format.
    ///
    /// Defaults to the repository the CI run is for.
    #[arg(long, default_value_t = default_github_repo())]
    pub github_repo: String,

    /// Base URL of the GitHub API, e.g. for GitHub Enterprise Server.
    ///
    /// Defaults to the API host of the CI run, or the public GitHub API.
    #[arg(long, default_value_t = default_api_base_url())]
    pub api_base_url: String,

    /// Commit hash shown in the report header.
    ///
    /// Defaults to the commit that triggered the CI run.
    #[arg(long, default_value_t = default_commit_hash())]
    pub commit_hash: String,

    /// How many base branch commits to walk back when looking for the
    /// baseline report. Zero disables the lookup.
    ///
    /// The window counts commits, not PRs: with squash merges the two
    /// coincide, but with rebase or merge-commit merges a single PR can
    /// span many commits, so a larger window may be needed.
    #[arg(long, default_value_t = DEFAULT_BASELINE_COMMIT_LOOKBACK)]
    pub baseline_commit_lookback: usize,
}

impl GithubReportArgs {
    /// Builds a [`GithubPrReporter`] targeting the configured PR. Fails if
    /// the target cannot be fully resolved, so call this before doing any
    /// expensive work.
    pub fn reporter(&self, marker: &str) -> Result<GithubPrReporter> {
        let pr_number: u64 = self.pr_number.trim().parse().with_context(|| {
            format!(
                "invalid PR number {:?}; pass --pr-number or run on a pull_request-triggered CI job",
                self.pr_number
            )
        })?;
        GithubPrReporter::new(GithubPrReporterConfig {
            repo: self.github_repo.clone(),
            pr_number,
            token: self.github_token.clone(),
            marker: marker.to_string(),
            api_base_url: self.api_base_url.clone(),
            // An empty hash (e.g. outside CI) means unset, so the header
            // falls back to "Local execution".
            commit_hash: Some(self.commit_hash.clone()).filter(|hash| !hash.trim().is_empty()),
            baseline_commit_lookback: self.baseline_commit_lookback,
            ..Default::default()
        })
    }
}

impl fmt::Debug for GithubReportArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubReportArgs")
            .field("github_token", &"<redacted>")
            .field("pr_number", &self.pr_number)
            .field("github_repo", &self.github_repo)
            .field("api_base_url", &self.api_base_url)
            .field("commit_hash", &self.commit_hash)
            .field("baseline_commit_lookback", &self.baseline_commit_lookback)
            .finish()
    }
}
