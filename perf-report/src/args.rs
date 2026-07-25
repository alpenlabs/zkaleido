use std::{env, fmt};

use anyhow::{Context, Result};
use clap::Args;

use crate::github::GithubPrReporter;

/// Returns the PR number parsed from the `GITHUB_REF` env var set by GitHub
/// Actions (`refs/pull/<number>/merge` on pull_request-triggered runs),
/// `None` on any other trigger or outside of CI.
fn pr_number_from_env() -> Option<u64> {
    let github_ref = env::var("GITHUB_REF").ok()?;
    github_ref
        .strip_prefix("refs/pull/")?
        .split('/')
        .next()?
        .parse()
        .ok()
}

/// Returns the repository from the `GITHUB_REPOSITORY` env var set by
/// GitHub Actions, `None` outside of CI.
fn repo_from_env() -> Option<String> {
    env::var("GITHUB_REPOSITORY").ok()
}

/// Returns the commit hash from the `GITHUB_SHA` env var set by GitHub
/// Actions, `None` outside of CI.
fn commit_hash_from_env() -> Option<String> {
    env::var("GITHUB_SHA").ok()
}

/// Returns the API base URL from the `GITHUB_API_URL` env var set by GitHub
/// Actions (which points at the enterprise host on GHES), `None` outside of
/// CI.
fn api_base_url_from_env() -> Option<String> {
    env::var("GITHUB_API_URL").ok()
}

/// CLI arguments for posting a performance report to a GitHub PR.
///
/// Meant to be embedded in a binary's argument struct via
/// `#[command(flatten)]`, either directly or as `Option<GithubReportArgs>`
/// to make "was any reporting flag given" drive whether to post. Values not
/// given on the command line are filled from the GitHub Actions environment
/// when [`reporter`](Self::reporter) is called, so env vars alone never
/// count as the group being present.
#[derive(Args, Clone)]
pub struct GithubReportArgs {
    /// The GitHub token for authentication.
    #[arg(long)]
    pub github_token: Option<String>,

    /// The GitHub PR number to comment on.
    ///
    /// Defaults to the PR that triggered the CI run.
    #[arg(long)]
    pub pr_number: Option<u64>,

    /// GitHub repository in `owner/repo` format.
    ///
    /// Defaults to the repository the CI run is for.
    #[arg(long)]
    pub github_repo: Option<String>,

    /// Commit hash shown in the report header.
    ///
    /// Defaults to the commit that triggered the CI run.
    #[arg(long)]
    pub commit_hash: Option<String>,
}

impl GithubReportArgs {
    /// Builds a [`GithubPrReporter`] targeting the configured PR, filling
    /// values not given on the command line from the GitHub Actions
    /// environment. Fails if the target cannot be fully resolved, so call
    /// this before doing any expensive work.
    pub fn reporter(&self, marker: &str) -> Result<GithubPrReporter> {
        let repo = self
            .github_repo
            .clone()
            .or_else(repo_from_env)
            .context("github repo not provided and GITHUB_REPOSITORY is not set")?;
        let pr_number = self
            .pr_number
            .or_else(pr_number_from_env)
            .context("PR number not provided and GITHUB_REF is not a pull request ref")?;
        let token = self
            .github_token
            .as_deref()
            .context("github token not provided")?;

        let mut reporter = GithubPrReporter::new(&repo, pr_number, token, marker)?;
        if let Some(api_base_url) = api_base_url_from_env() {
            reporter = reporter.with_api_base_url(&api_base_url);
        }
        if let Some(hash) = self.commit_hash.clone().or_else(commit_hash_from_env) {
            reporter = reporter.with_commit_hash(&hash);
        }
        Ok(reporter)
    }
}

impl fmt::Debug for GithubReportArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubReportArgs")
            .field(
                "github_token",
                &self.github_token.as_ref().map(|_| "<redacted>"),
            )
            .field("pr_number", &self.pr_number)
            .field("github_repo", &self.github_repo)
            .field("commit_hash", &self.commit_hash)
            .finish()
    }
}
