use std::{env, fmt, fs};

use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;

use crate::github::{
    DEFAULT_API_BASE_URL, DEFAULT_BASELINE_COMMIT_LOOKBACK, DEFAULT_EXPECTED_COMMENT_AUTHOR,
    GithubPrReporter, GithubPrReporterConfig,
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

/// Returns `pull_request.<path>` from the webhook payload at
/// `GITHUB_EVENT_PATH` (set by GitHub Actions for every trigger), empty if
/// the env var is unset, the file can't be read, or the trigger wasn't
/// `pull_request`.
///
/// This reflects what GitHub actually resolved when the event fired, fixed
/// for the lifetime of the run. A live API lookup is a poor substitute for
/// values that can change over time (the base branch can advance, the PR
/// head can get new commits): resolving live would silently pick up
/// whatever the PR looks like when the lookup happens to run, not what
/// `GITHUB_SHA` was actually built from.
fn default_pull_request_field(path: &[&str]) -> String {
    let Ok(event_path) = env::var("GITHUB_EVENT_PATH") else {
        return String::new();
    };
    let Ok(contents) = fs::read_to_string(event_path) else {
        return String::new();
    };
    let Ok(event) = serde_json::from_str::<Value>(&contents) else {
        return String::new();
    };
    let mut value = &event["pull_request"];
    for segment in path {
        value = &value[*segment];
    }
    value.as_str().map(str::to_string).unwrap_or_default()
}

/// Returns the base branch ref name from the triggering event. See
/// [`default_pull_request_field`].
fn default_base_ref() -> String {
    default_pull_request_field(&["base", "ref"])
}

/// Returns the base branch commit SHA from the triggering event. See
/// [`default_pull_request_field`].
fn default_base_sha() -> String {
    default_pull_request_field(&["base", "sha"])
}

/// Returns the PR head commit SHA from the triggering event. See
/// [`default_pull_request_field`].
fn default_head_sha() -> String {
    default_pull_request_field(&["head", "sha"])
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

    /// Base branch ref name to anchor the baseline commit walk to.
    ///
    /// Defaults to the base ref of the triggering pull_request event.
    /// Falls back to a live lookup of the PR's current base outside of CI.
    #[arg(long, default_value_t = default_base_ref())]
    pub base_ref: String,

    /// Base branch commit SHA to anchor the baseline commit walk to.
    ///
    /// Defaults to the base SHA of the triggering pull_request event: the
    /// commit GitHub actually resolved the PR's base to when the event
    /// fired. Falls back to a live lookup of the PR's current base tip
    /// outside of CI, which is racy if the base branch advances before the
    /// lookup runs.
    #[arg(long, default_value_t = default_base_sha())]
    pub base_sha: String,

    /// Expected GitHub login of the sticky report comment's author.
    ///
    /// A comment is only ever treated as a genuine report -- to patch when
    /// posting, or to read back as a baseline -- when it was posted by
    /// this identity; otherwise anyone who can comment on a PR could forge
    /// a fake report. Defaults to the identity GitHub attributes comments
    /// to when posted with the default `GITHUB_TOKEN`; override this if
    /// posting with a different token (a custom bot account, a GitHub App
    /// installation, or a PAT).
    #[arg(long, default_value = DEFAULT_EXPECTED_COMMENT_AUTHOR)]
    pub expected_comment_author: String,

    /// PR head commit SHA this run is testing.
    ///
    /// Defaults to the head SHA of the triggering pull_request event.
    /// Before posting, this is checked against the PR's current head; a
    /// mismatch means a newer push has already been tested (concurrency
    /// cancellation only catches *overlapping* runs, not a re-run of an
    /// older completed one), so the report is skipped instead of
    /// overwriting a fresher one. Empty (e.g. outside CI) disables the
    /// check.
    #[arg(long, default_value_t = default_head_sha())]
    pub head_sha: String,
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
            // Empty (e.g. outside CI or a non-pull_request trigger) means
            // unset, so the baseline anchor falls back to a live lookup.
            base_ref: Some(self.base_ref.clone()).filter(|s| !s.trim().is_empty()),
            base_sha: Some(self.base_sha.clone()).filter(|s| !s.trim().is_empty()),
            expected_comment_author: self.expected_comment_author.clone(),
            head_sha: Some(self.head_sha.clone()).filter(|s| !s.trim().is_empty()),
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
            .field("base_ref", &self.base_ref)
            .field("base_sha", &self.base_sha)
            .field("expected_comment_author", &self.expected_comment_author)
            .field("head_sha", &self.head_sha)
            .finish()
    }
}
