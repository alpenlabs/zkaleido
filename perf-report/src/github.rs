use std::{env, fmt};

use anyhow::{Result, anyhow, bail};
use reqwest::{Client, RequestBuilder};
use serde_json::json;

use crate::{format::render_report, report::ZkVmResults};

/// Returns the commit hash of the workflow run from the `GITHUB_SHA` env var
/// set by GitHub Actions, `None` outside of CI.
fn detect_commit_hash() -> Option<String> {
    env::var("GITHUB_SHA").ok().filter(|sha| !sha.is_empty())
}

/// Returns the report header identifying what was benchmarked.
fn format_header(commit_hash: Option<&str>) -> String {
    match commit_hash {
        Some(hash) => {
            let short_commit: String = hash.chars().take(8).collect();
            format!("*Commit*: {short_commit}")
        }
        None => "*Local execution*".to_string(),
    }
}

/// Default `User-Agent` header sent with GitHub API requests.
pub const DEFAULT_USER_AGENT: &str = "zkaleido-perf-report";

/// Posts performance reports as a sticky comment on a GitHub PR.
///
/// The posted comment body is prefixed with an invisible HTML comment built
/// from `marker`, which is how subsequent posts find and update the existing
/// comment instead of stacking new ones. Use a marker that is unique per
/// report kind within a repository.
pub struct GithubPrReporter {
    /// Repository in `owner/name` form, e.g. `alpenlabs/zkaleido`.
    repo: String,
    /// Number of the PR to comment on.
    pr_number: String,
    /// GitHub token used for authentication.
    token: String,
    /// Identifier embedded in the comment to make it sticky.
    marker: String,
    /// `User-Agent` header sent with GitHub API requests.
    user_agent: String,
}

impl GithubPrReporter {
    /// Creates a reporter targeting the given PR.
    pub fn new(repo: &str, pr_number: &str, token: &str, marker: &str) -> Self {
        Self {
            repo: repo.to_string(),
            pr_number: pr_number.to_string(),
            token: token.to_string(),
            marker: marker.to_string(),
            user_agent: DEFAULT_USER_AGENT.to_string(),
        }
    }

    /// Overrides the `User-Agent` header sent with GitHub API requests.
    pub fn with_user_agent(mut self, user_agent: &str) -> Self {
        self.user_agent = user_agent.to_string();
        self
    }

    /// Renders the results and posts them to the PR, updating the existing
    /// sticky comment if one is found.
    ///
    /// The commit hash shown in the report header is taken from the
    /// `GITHUB_SHA` env var set by GitHub Actions.
    pub async fn post_report(&self, results: &[ZkVmResults]) -> Result<()> {
        let commit_hash = detect_commit_hash();
        let header = format_header(commit_hash.as_deref());
        let report_text = format!("{header}\n{}", render_report(results));
        // TODO: emit GitHub markdown directly in the formatters instead of
        // the `*bold*` -> `**bold**` rewrite, once all consumers go through
        // this crate.
        self.post(&report_text.replace('*', "**")).await
    }

    /// Posts the message to the PR, updating the existing sticky comment if
    /// one is found.
    async fn post(&self, message: &str) -> Result<()> {
        if self.repo.trim().is_empty() {
            bail!("github repo is required");
        }
        if self.pr_number.trim().is_empty() {
            bail!("PR number is required");
        }
        if self.token.trim().is_empty() {
            bail!("github token is required");
        }
        if self.marker.trim().is_empty() {
            bail!("comment marker is required");
        }

        let hidden_marker = format!("<!-- {} -->", self.marker);
        let body = format!("{hidden_marker}\n{message}");

        let client = Client::new();
        let comments_url = format!(
            "https://api.github.com/repos/{}/issues/{}/comments?per_page=100",
            self.repo, self.pr_number
        );

        let comments_response = self
            .set_github_headers(client.get(&comments_url))
            .send()
            .await?;
        if !comments_response.status().is_success() {
            let status = comments_response.status();
            let body = comments_response.text().await.unwrap_or_default();
            bail!("failed to fetch PR comments ({status}): {body}");
        }

        let comments: Vec<serde_json::Value> = comments_response
            .json()
            .await
            .map_err(|e| anyhow!("failed to decode PR comments response: {e}"))?;

        let sticky_comment = comments.iter().find(|comment| {
            comment["body"]
                .as_str()
                .map(|body| body.contains(&hidden_marker))
                .unwrap_or(false)
        });

        let request = if let Some(existing_comment) = sticky_comment {
            let comment_url = existing_comment["url"]
                .as_str()
                .ok_or_else(|| anyhow!("existing sticky comment did not include url field"))?;
            client.patch(comment_url)
        } else {
            client.post(&comments_url)
        };

        let response = self
            .set_github_headers(request)
            .json(&json!({ "body": body }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            bail!("failed to post/update PR comment ({status}): {body}");
        }

        Ok(())
    }

    fn set_github_headers(&self, builder: RequestBuilder) -> RequestBuilder {
        builder
            .header("Authorization", format!("Bearer {}", self.token))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", &self.user_agent)
    }
}

impl fmt::Debug for GithubPrReporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubPrReporter")
            .field("repo", &self.repo)
            .field("pr_number", &self.pr_number)
            .field("token", &"<redacted>")
            .field("marker", &self.marker)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}
