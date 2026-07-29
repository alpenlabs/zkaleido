use std::fmt;

use anyhow::{Result, anyhow, bail};
use reqwest::{Client, RequestBuilder};
use serde_json::{Value, json};

use crate::{format::render_report, payload::ReportPayload, report::ZkVmResults};

/// Default number of base-branch commits to walk back when looking for a
/// baseline.
///
/// The window counts commits, not PRs. Under squash merging every base
/// branch commit corresponds to one PR, so this spans ~20 PRs. Under
/// rebase or merge-commit merging a single PR lands all of its commits on
/// the base branch, so one large PR can consume most of the window;
/// configure a larger lookback in such repositories.
pub const DEFAULT_BASELINE_COMMIT_LOOKBACK: usize = 20;

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

/// Returns the number of the merged pull request in `merged_pulls` whose
/// merge commit is `sha`.
fn find_pr_for_merge_commit(merged_pulls: &[Value], sha: &str) -> Option<u64> {
    merged_pulls
        .iter()
        .find(|pull| !pull["merged_at"].is_null() && pull["merge_commit_sha"].as_str() == Some(sha))
        .and_then(|pull| pull["number"].as_u64())
}

/// Returns the first 8 characters of a commit hash.
fn short_hash(hash: &str) -> String {
    hash.chars().take(8).collect()
}

/// Why no baseline is available, used by [`format_header`] to describe a
/// missing baseline accurately instead of always reading as a clean miss.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NoBaselineReason {
    /// Baseline lookup is disabled (`baseline_commit_lookback == 0`).
    LookupDisabled,
    /// The lookup ran to completion and found nothing within the window.
    NotFound,
    /// The lookup itself failed, e.g. a network or API error.
    LookupFailed,
}

/// Returns the report header identifying what was benchmarked and which
/// baseline it is compared against.
fn format_header(
    commit_hash: Option<&str>,
    baseline: Option<&BaselineReport>,
    no_baseline_reason: NoBaselineReason,
) -> String {
    let mut lines = vec![match commit_hash {
        Some(hash) => format!("**Commit**: {}", short_hash(hash)),
        None => "**Local execution**".to_string(),
    }];
    match baseline {
        Some(baseline) => lines.push(format!(
            "**Baseline**: #{} ({})",
            baseline.pr_number,
            short_hash(&baseline.commit_hash)
        )),
        // The lookup ran but yielded no baseline (e.g. no merged PR with a
        // readable report yet); say so to distinguish "nothing to compare
        // against" from lookup being disabled.
        None if no_baseline_reason == NoBaselineReason::NotFound => {
            lines.push("**Baseline**: none found".to_string())
        }
        // The lookup didn't run to completion, so "none found" would
        // misrepresent a transient failure as a confirmed clean miss.
        None if no_baseline_reason == NoBaselineReason::LookupFailed => {
            lines.push("**Baseline**: lookup failed, see job logs".to_string())
        }
        None => {}
    }
    lines.join("\n")
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
    /// How many base-branch commits to walk back when looking for a
    /// baseline. Zero disables baseline lookup. See
    /// [`DEFAULT_BASELINE_COMMIT_LOOKBACK`] for how the window relates to
    /// the repository's merge strategy.
    pub baseline_commit_lookback: usize,
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
            baseline_commit_lookback: DEFAULT_BASELINE_COMMIT_LOOKBACK,
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
            .field("baseline_commit_lookback", &self.baseline_commit_lookback)
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
    /// branch. The base branch is resolved from the PR being reported on,
    /// so no configuration is needed and any trigger type works. Walks the
    /// base branch history commit by commit, matching each commit to a
    /// merged PR by `merge_commit_sha` rather than GitHub's commit-to-PR
    /// association endpoint, which only reports merged PRs for commits
    /// reachable from the repository's default branch and would otherwise
    /// miss every PR merged into a non-default base. Commits without a
    /// matching merged PR (direct pushes) and PRs without a readable report
    /// (failed perf job, predates the embedded payload) are skipped in
    /// favor of an older baseline. Returns `None` when the lookback is zero
    /// or nothing is found within the lookback window; a missing baseline
    /// only degrades the report to absolute numbers, so callers can treat
    /// errors the same way.
    pub async fn fetch_baseline(&self) -> Result<Option<BaselineReport>> {
        // Guard explicitly: the GitHub API treats `per_page=0` as "use the
        // default page size" rather than "no commits".
        if self.config.baseline_commit_lookback == 0 {
            return Ok(None);
        }

        let client = Client::new();
        let base_branch = self.fetch_pr_base_branch(&client).await?;
        // TODO: lookbacks above 100 are silently capped by the GitHub API,
        // which serves at most one page of commits or merged pull requests;
        // paginate to support larger windows.
        let lookback = self.config.baseline_commit_lookback.to_string();
        let commits_url = format!(
            "{}/repos/{}/commits",
            self.config.api_base_url, self.config.repo
        );
        let commits = self
            .get_json_array(
                &client,
                &commits_url,
                &[("sha", base_branch.as_str()), ("per_page", &lookback)],
                "base branch commits",
            )
            .await?;

        let pulls_url = format!(
            "{}/repos/{}/pulls",
            self.config.api_base_url, self.config.repo
        );
        let merged_pulls = self
            .get_json_array(
                &client,
                &pulls_url,
                &[
                    ("base", base_branch.as_str()),
                    ("state", "closed"),
                    ("sort", "updated"),
                    ("direction", "desc"),
                    ("per_page", &lookback),
                ],
                "merged pull requests",
            )
            .await?;

        for commit in &commits {
            let Some(sha) = commit["sha"].as_str() else {
                continue;
            };
            let Some(pr_number) = find_pr_for_merge_commit(&merged_pulls, sha) else {
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
    /// sticky comment if one is found, with per-program deltas when a
    /// `baseline` is given. The posted comment also embeds the results as a
    /// hidden machine-readable payload, which is what later runs read back
    /// as their baseline.
    ///
    /// `baseline_lookup_failed` should be set when the caller's
    /// [`Self::fetch_baseline`] call returned `Err` rather than `Ok(None)`,
    /// so the posted header can say the lookup failed instead of implying a
    /// confirmed clean miss.
    pub async fn post_report(
        &self,
        results: &[ZkVmResults],
        baseline: Option<&BaselineReport>,
        baseline_lookup_failed: bool,
    ) -> Result<()> {
        let no_baseline_reason = if baseline_lookup_failed {
            NoBaselineReason::LookupFailed
        } else if self.config.baseline_commit_lookback > 0 {
            NoBaselineReason::NotFound
        } else {
            NoBaselineReason::LookupDisabled
        };
        let header = format_header(
            self.config.commit_hash.as_deref(),
            baseline,
            no_baseline_reason,
        );
        let payload = ReportPayload::from(results).embed()?;
        let report = render_report(results, baseline.map(|baseline| &baseline.payload));
        let report_text = format!("{header}\n{report}\n{payload}");
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

    /// Returns the base branch of the PR the report is posted on.
    async fn fetch_pr_base_branch(&self, client: &Client) -> Result<String> {
        let url = format!(
            "{}/repos/{}/pulls/{}",
            self.config.api_base_url, self.config.repo, self.config.pr_number
        );
        let pr = self.get_json(client, &url, &[], "pull request").await?;
        pr["base"]["ref"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("pull request response did not include base.ref"))
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
        self.get_json_array(client, &self.comments_url(pr_number), &[], "PR comments")
            .await
    }

    /// Fetches `url` and decodes the response as JSON. `query` is appended
    /// as URL-encoded query parameters rather than interpolated into
    /// `url` directly, so values with URL-significant characters (e.g. a
    /// branch name like `release#1`) can't truncate or redirect the
    /// request.
    async fn get_json(
        &self,
        client: &Client,
        url: &str,
        query: &[(&str, &str)],
        what: &str,
    ) -> Result<Value> {
        let response = self
            .set_github_headers(client.get(url).query(query))
            .send()
            .await?;
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

    /// Fetches `url` and decodes the response as a JSON array. See
    /// [`Self::get_json`] for `query`.
    async fn get_json_array(
        &self,
        client: &Client,
        url: &str,
        query: &[(&str, &str)],
        what: &str,
    ) -> Result<Vec<Value>> {
        match self.get_json(client, url, query, what).await? {
            Value::Array(items) => Ok(items),
            _ => bail!("expected a JSON array in {what} response"),
        }
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
    fn finds_pr_by_merge_commit_sha() {
        let merged_pulls = vec![
            json!({"number": 1, "merged_at": null, "merge_commit_sha": "abc123"}),
            json!({"number": 2, "merged_at": "2026-07-01T00:00:00Z", "merge_commit_sha": "def456"}),
            json!({"number": 3, "merged_at": "2026-07-01T00:00:00Z", "merge_commit_sha": "abc123"}),
        ];
        assert_eq!(find_pr_for_merge_commit(&merged_pulls, "abc123"), Some(3));
        assert_eq!(find_pr_for_merge_commit(&merged_pulls, "def456"), Some(2));
        assert_eq!(find_pr_for_merge_commit(&merged_pulls, "missing"), None);
    }
}
