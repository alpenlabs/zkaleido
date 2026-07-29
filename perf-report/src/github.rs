use std::fmt;

use anyhow::{Result, anyhow, bail};
use reqwest::{Client, RequestBuilder};
use serde_json::json;

use crate::{format::render_report, payload::ReportPayload, report::ZkVmResults};

/// Returns the report header identifying what was benchmarked.
fn format_header(commit_hash: Option<&str>) -> String {
    match commit_hash {
        Some(hash) => {
            let short_commit: String = hash.chars().take(8).collect();
            format!("**Commit**: {short_commit}")
        }
        None => "**Local execution**".to_string(),
    }
}

/// Default `User-Agent` header sent with GitHub API requests.
pub const DEFAULT_USER_AGENT: &str = "zkaleido-perf-report";

/// Default base URL of the GitHub REST API.
pub const DEFAULT_API_BASE_URL: &str = "https://api.github.com";

/// Configuration for a [`GithubPrReporter`], taken in full by
/// [`GithubPrReporter::new`].
///
/// `repo`, `pr_number`, `token`, and `marker` have no usable defaults and
/// must be filled in; the remaining fields can be left to [`Default`] via
/// struct-update syntax (`..Default::default()`).
#[derive(Clone)]
pub struct GithubPrReporterConfig {
    /// Repository in `owner/name` form, e.g. `alpenlabs/zkaleido`.
    pub repo: String,
    /// Number of the PR to comment on.
    pub pr_number: u64,
    /// GitHub token used for authentication.
    pub token: String,
    /// Identifier embedded in the comment to make it sticky. Use a marker
    /// that is unique per report kind within a repository.
    pub marker: String,
    /// `User-Agent` header sent with GitHub API requests.
    pub user_agent: String,
    /// Base URL of the GitHub API. Point it at the API host when targeting
    /// a GitHub Enterprise Server instance.
    pub api_base_url: String,
    /// Commit hash shown in the report header, `None` for local runs.
    pub commit_hash: Option<String>,
}

impl Default for GithubPrReporterConfig {
    fn default() -> Self {
        Self {
            repo: String::new(),
            pr_number: 0,
            token: String::new(),
            marker: String::new(),
            user_agent: DEFAULT_USER_AGENT.to_string(),
            api_base_url: DEFAULT_API_BASE_URL.to_string(),
            commit_hash: None,
        }
    }
}

impl fmt::Debug for GithubPrReporterConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubPrReporterConfig")
            .field("repo", &self.repo)
            .field("pr_number", &self.pr_number)
            .field("token", &"<redacted>")
            .field("marker", &self.marker)
            .field("user_agent", &self.user_agent)
            .field("api_base_url", &self.api_base_url)
            .field("commit_hash", &self.commit_hash)
            .finish()
    }
}

/// Posts performance reports as a sticky comment on a GitHub PR.
///
/// The posted comment body is prefixed with an invisible HTML comment built
/// from the configured marker, which is how subsequent posts find and
/// update the existing comment instead of stacking new ones.
#[derive(Debug)]
pub struct GithubPrReporter {
    config: GithubPrReporterConfig,
}

impl GithubPrReporter {
    /// Creates a reporter from the full configuration. Fails if any
    /// required field is blank, so misconfiguration surfaces at
    /// construction rather than when the report is posted.
    pub fn new(mut config: GithubPrReporterConfig) -> Result<Self> {
        if config.repo.trim().is_empty() {
            bail!("github repo is required");
        }
        if config.token.trim().is_empty() {
            bail!("github token is required");
        }
        if config.marker.trim().is_empty() {
            bail!("comment marker is required");
        }
        if config.api_base_url.trim().is_empty() {
            bail!("github API base url is required");
        }
        config.api_base_url = config.api_base_url.trim_end_matches('/').to_string();
        Ok(Self { config })
    }

    /// Renders the results and posts them to the PR, updating the existing
    /// sticky comment if one is found. The posted comment also embeds the
    /// results as a hidden machine-readable payload, which is what later
    /// runs read back as their baseline.
    pub async fn post_report(&self, results: &[ZkVmResults]) -> Result<()> {
        let header = format_header(self.config.commit_hash.as_deref());
        let payload = ReportPayload::from(results).embed()?;
        let report_text = format!("{header}\n{}\n{payload}", render_report(results));
        self.post(&report_text).await
    }

    /// Posts the message to the PR, updating the existing sticky comment if
    /// one is found.
    async fn post(&self, message: &str) -> Result<()> {
        let hidden_marker = format!("<!-- {} -->", self.config.marker);
        let body = format!("{hidden_marker}\n{message}");

        // TODO: set a request timeout on the client so a hung connection
        // fails on its own. Acceptable for now: this is expected to run in
        // CI, where the job-level timeout covers it.
        let client = Client::new();
        // TODO: follow the `Link` header to paginate instead of fetching a
        // single page; a sticky comment past the first 100 comments is
        // missed and a duplicate gets created. Acceptable for now: the
        // comment is posted right after the first CI run of a PR, so it
        // lands within the first page.
        let comments_url = format!(
            "{}/repos/{}/issues/{}/comments?per_page=100",
            self.config.api_base_url, self.config.repo, self.config.pr_number
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

        // TODO: deserialize the comments into a typed struct instead of
        // poking at `serde_json::Value`, for better errors when the
        // response doesn't have the expected shape.
        let comments: Vec<serde_json::Value> = comments_response
            .json()
            .await
            .map_err(|e| anyhow!("failed to decode PR comments response: {e}"))?;

        // Only a body that *starts* with the marker counts: the reporter
        // always writes the marker first, so a comment that merely quotes
        // it (e.g. a human discussing this report) is never mistaken for
        // the sticky comment and overwritten.
        let sticky_comment = comments.iter().find(|comment| {
            comment["body"]
                .as_str()
                .map(|body| body.starts_with(&hidden_marker))
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
            .header("Authorization", format!("Bearer {}", self.config.token))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", &self.config.user_agent)
    }
}
