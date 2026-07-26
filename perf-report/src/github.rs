use std::fmt;

use anyhow::{Result, anyhow, bail};
use reqwest::{Client, RequestBuilder};
use serde_json::{Value, json};

use crate::{format::render_report, payload::ReportPayload, report::ZkVmResults};

/// How many base-branch commits to walk back when looking for a baseline.
const BASELINE_COMMIT_LOOKBACK: usize = 20;

/// A performance report recovered from an already-merged PR, used as the
/// baseline to diff a new report against.
#[derive(Debug, Clone)]
pub struct BaselineReport {
    /// Number of the PR the baseline report was posted on.
    pub pr_number: u64,
    /// The base branch commit the baseline corresponds to.
    pub commit_hash: String,
    /// The machine-readable results recovered from the report comment.
    pub payload: ReportPayload,
}

/// Returns the first comment whose body starts with the hidden marker.
///
/// Only a body that *starts* with the marker counts: the reporter always
/// writes the marker first, so a comment that merely quotes it (e.g. a
/// human discussing this report) is never mistaken for the sticky comment
/// and overwritten.
fn find_sticky_comment<'a>(comments: &'a [Value], hidden_marker: &str) -> Option<&'a Value> {
    comments.iter().find(|comment| {
        comment["body"]
            .as_str()
            .map(|body| body.starts_with(hidden_marker))
            .unwrap_or(false)
    })
}

/// Returns the number of the first of `pulls` that was merged into
/// `base_branch`.
fn first_merged_pr(pulls: &[Value], base_branch: &str) -> Option<u64> {
    pulls
        .iter()
        .find(|pull| {
            !pull["merged_at"].is_null() && pull["base"]["ref"].as_str() == Some(base_branch)
        })
        .and_then(|pull| pull["number"].as_u64())
}

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
    /// Base branch searched for the baseline report, `None` to disable
    /// baseline lookup.
    pub base_branch: Option<String>,
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
            base_branch: None,
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
            .field("base_branch", &self.base_branch)
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

    /// Fetches the baseline report to diff against: the payload embedded in
    /// the sticky report comment of the most recently merged PR on the base
    /// branch. Walks the base branch history commit by commit, so commits
    /// without a merged PR (direct pushes) and PRs without a readable
    /// report (failed perf job, predates the embedded payload) are skipped
    /// in favor of an older baseline. Returns `None` when no base branch is
    /// configured or nothing is found within the lookback window.
    pub async fn fetch_baseline(&self) -> Result<Option<BaselineReport>> {
        let Some(base_branch) = self.config.base_branch.as_deref() else {
            return Ok(None);
        };

        let client = Client::new();
        let commits_url = format!(
            "{}/repos/{}/commits?sha={base_branch}&per_page={BASELINE_COMMIT_LOOKBACK}",
            self.config.api_base_url, self.config.repo
        );
        let commits = self
            .get_json_array(&client, &commits_url, "base branch commits")
            .await?;

        for commit in &commits {
            let Some(sha) = commit["sha"].as_str() else {
                continue;
            };
            let pulls_url = format!(
                "{}/repos/{}/commits/{sha}/pulls",
                self.config.api_base_url, self.config.repo
            );
            let pulls = self
                .get_json_array(&client, &pulls_url, "associated pull requests")
                .await?;
            let Some(pr_number) = first_merged_pr(&pulls, base_branch) else {
                continue;
            };
            let comments = self.fetch_comments(&client, pr_number).await?;
            let Some(payload) = find_sticky_comment(&comments, &self.hidden_marker())
                .and_then(|comment| comment["body"].as_str())
                .and_then(ReportPayload::extract)
            else {
                continue;
            };
            return Ok(Some(BaselineReport {
                pr_number,
                commit_hash: sha.to_string(),
                payload,
            }));
        }
        Ok(None)
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
        let hidden_marker = self.hidden_marker();
        let body = format!("{hidden_marker}\n{message}");

        // TODO: set a request timeout on the client so a hung connection
        // fails on its own. Acceptable for now: this is expected to run in
        // CI, where the job-level timeout covers it.
        let client = Client::new();
        let comments = self.fetch_comments(&client, self.config.pr_number).await?;
        let sticky_comment = find_sticky_comment(&comments, &hidden_marker);

        let request = if let Some(existing_comment) = sticky_comment {
            let comment_url = existing_comment["url"]
                .as_str()
                .ok_or_else(|| anyhow!("existing sticky comment did not include url field"))?;
            client.patch(comment_url)
        } else {
            client.post(self.comments_url(self.config.pr_number))
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

    /// Returns the hidden HTML comment that identifies the sticky comment.
    fn hidden_marker(&self) -> String {
        format!("<!-- {} -->", self.config.marker)
    }

    fn comments_url(&self, pr_number: u64) -> String {
        // TODO: follow the `Link` header to paginate instead of fetching a
        // single page; a sticky comment past the first 100 comments is
        // missed and a duplicate gets created. Acceptable for now: the
        // comment is posted right after the first CI run of a PR, so it
        // lands within the first page.
        format!(
            "{}/repos/{}/issues/{pr_number}/comments?per_page=100",
            self.config.api_base_url, self.config.repo
        )
    }

    async fn fetch_comments(&self, client: &Client, pr_number: u64) -> Result<Vec<Value>> {
        self.get_json_array(client, &self.comments_url(pr_number), "PR comments")
            .await
    }

    /// Fetches `url` and decodes the response as a JSON array.
    async fn get_json_array(&self, client: &Client, url: &str, what: &str) -> Result<Vec<Value>> {
        let response = self.set_github_headers(client.get(url)).send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            bail!("failed to fetch {what} ({status}): {body}");
        }

        // TODO: deserialize the responses into typed structs instead of
        // poking at `serde_json::Value`, for better errors when a response
        // doesn't have the expected shape.
        response
            .json()
            .await
            .map_err(|e| anyhow!("failed to decode {what} response: {e}"))
    }

    fn set_github_headers(&self, builder: RequestBuilder) -> RequestBuilder {
        builder
            .header("Authorization", format!("Bearer {}", self.config.token))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", &self.config.user_agent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_sticky_comment_by_marker() {
        let comments = vec![
            json!({"body": "unrelated comment"}),
            json!({"body": "quoting the `<!-- marker -->` trick", "url": "http://c/2"}),
            json!({"body": "<!-- marker -->\nreport", "url": "http://c/3"}),
            json!({"no_body": true}),
        ];
        let found = find_sticky_comment(&comments, "<!-- marker -->").unwrap();
        assert_eq!(found["url"], "http://c/3");
        assert!(find_sticky_comment(&comments, "<!-- other -->").is_none());
    }

    #[test]
    fn picks_merged_pr_targeting_base_branch() {
        let pulls = vec![
            json!({"number": 1, "merged_at": null, "base": {"ref": "main"}}),
            json!({"number": 2, "merged_at": "2026-07-01T00:00:00Z", "base": {"ref": "dev"}}),
            json!({"number": 3, "merged_at": "2026-07-01T00:00:00Z", "base": {"ref": "main"}}),
        ];
        assert_eq!(first_merged_pr(&pulls, "main"), Some(3));
        assert_eq!(first_merged_pr(&pulls, "dev"), Some(2));
        assert_eq!(first_merged_pr(&pulls, "release"), None);
    }
}
