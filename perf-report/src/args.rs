use std::{env, fmt};

use clap::Args;

use crate::github::GithubPrReporter;

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
        .filter(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
        .map(str::to_string)
        .unwrap_or_default()
}

/// Returns the repository from the `GITHUB_REPOSITORY` env var set by
/// GitHub Actions, empty outside of CI.
fn default_github_repo() -> String {
    env::var("GITHUB_REPOSITORY").unwrap_or_default()
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
}

impl GithubReportArgs {
    /// Builds a [`GithubPrReporter`] targeting the configured PR.
    pub fn reporter(&self, marker: &str) -> GithubPrReporter {
        GithubPrReporter::new(
            &self.github_repo,
            &self.pr_number,
            &self.github_token,
            marker,
        )
    }
}

impl fmt::Debug for GithubReportArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubReportArgs")
            .field("github_token", &"<redacted>")
            .field("pr_number", &self.pr_number)
            .field("github_repo", &self.github_repo)
            .finish()
    }
}
