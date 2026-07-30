use std::{collections::HashMap, fmt};

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

/// A fixed point to anchor the baseline commit walk to: the PR's base
/// branch name and the commit it pointed to when resolved.
///
/// Resolve this once, before doing any long-running work, and reuse it for
/// [`GithubPrReporter::fetch_baseline`]. Re-resolving the base branch late
/// (e.g. after benchmarks run) would let the walk start from whatever the
/// branch has advanced to by then rather than what was actually tested.
#[derive(Debug, Clone)]
pub struct BaselineAnchor {
    base_ref: String,
    base_sha: String,
}

/// Returns the first comment authored by `expected_author` whose body
/// starts with the hidden marker.
///
/// Both conditions matter: a body that only *starts* with the marker
/// means the reporter always writes it first, so a comment that merely
/// quotes it (e.g. a human discussing this report) is never mistaken for
/// the sticky comment and overwritten. The author check means a comment
/// is never trusted purely because of what it says -- on a public repo,
/// anyone who can comment on a PR can post one starting with the marker
/// and an arbitrary embedded payload before the real CI job runs; without
/// checking who posted it, such a forged comment would be indistinguishable
/// from a genuine report, and if that PR later merges, a future
/// [`GithubPrReporter::fetch_baseline`] walk would trust the fabricated
/// numbers as its baseline.
fn find_sticky_comment<'a>(
    comments: &'a [Value],
    hidden_marker: &str,
    expected_author: &str,
) -> Option<&'a Value> {
    comments.iter().find(|comment| {
        let body_matches = comment["body"]
            .as_str()
            .is_some_and(|body| body.starts_with(hidden_marker));
        let author_matches = comment["user"]["login"].as_str() == Some(expected_author);
        body_matches && author_matches
    })
}

/// Returns the merged pull request in `merged_pulls` whose merge commit is
/// `sha`.
fn find_pr_for_merge_commit<'a>(merged_pulls: &'a [Value], sha: &str) -> Option<&'a Value> {
    merged_pulls
        .iter()
        .find(|pull| !pull["merged_at"].is_null() && pull["merge_commit_sha"].as_str() == Some(sha))
}

/// Returns whether `payload_head_sha` (a candidate's tested head, from its
/// embedded payload) matches `merged_head_sha` (that PR's own recorded
/// `head.sha`).
///
/// A run whose CI succeeded and posted for one head, followed by a further
/// push whose own CI run failed or was cancelled before it could post,
/// leaves the sticky comment holding an earlier head's results even
/// though a later head is what the PR actually merged. Both heads can
/// share the same tested base, so the base-only freshness check can't
/// catch this; comparing head identity closes that gap. A payload with no
/// `head_sha` (e.g. posted before this field existed) can't be verified
/// and is treated as not matching.
fn tested_correct_head(payload_head_sha: Option<&str>, merged_head_sha: &str) -> bool {
    payload_head_sha == Some(merged_head_sha)
}

/// Returns whether a merge commit whose first parent has author identity
/// `parent_author` (the `commit.author` object: name, email, and date)
/// landed via rebase-and-merge, given `pr_commits` (the PR's own commits,
/// oldest first, as returned by the GitHub API).
///
/// A clean git rebase preserves each commit's author name, email, and
/// author date exactly -- only the committer (and committer date) change,
/// since the committer becomes GitHub's merge machinery at merge time.
/// Author identity is a reliable signal even when the PR's branch was
/// based on an older point in the base branch's history: unlike a tree
/// comparison, it doesn't depend on the base being unchanged since the PR
/// branched, only on the rebase itself being clean. A tree comparison was
/// tried and discarded for exactly this reason: a real rebase reapplies
/// each commit's diff onto the new base, so its tree differs from the
/// original source commit's whenever the base actually changed in
/// between -- the very case this needs to detect.
///
/// A squash (or a single fast-forwarded commit) instead has a parent that
/// predates the PR entirely, authored by whoever committed to the base
/// branch at that point -- vanishingly unlikely to coincidentally match
/// this PR's own second-to-last commit's author identity and timestamp.
///
/// Callers should only reach for this after a direct one-hop check
/// against `payload.base_sha` has already failed -- that check is exact
/// and always correct when it succeeds, so this is only ever asked to
/// resolve genuinely ambiguous cases, never able to override a real
/// match.
///
/// A single-commit PR is excluded: squash and rebase are indistinguishable
/// for it (both land as exactly one commit), so there's nothing to tell
/// apart.
fn merge_looks_rebased(parent_author: &Value, pr_commits: &[Value]) -> bool {
    let Some(second_to_last) = pr_commits.len().checked_sub(2).map(|i| &pr_commits[i]) else {
        return false;
    };
    &second_to_last["commit"]["author"] == parent_author
}

/// Returns whether `payload` was tested against exactly the base state the
/// candidate's commit span landed on.
///
/// Walks back exactly `commit_count` first-parent hops from `merge_sha`
/// (the candidate's merge commit) -- one hop per commit this PR actually
/// landed on the base branch; see [`GithubPrReporter::resolve_landed_commit_count`]
/// for how that count is determined. `parent_of` should map each
/// base-branch commit's sha to its first parent's sha, built from the
/// already-fetched commit history.
///
/// The walk must stop at exactly `commit_count` hops rather than
/// continuing until *some* match turns up: the base branch's history is
/// linear and only grows, so searching further back would also find (and
/// wrongly accept) an older `base_sha` that the candidate was tested
/// against before some unrelated PR advanced the base in between -- the
/// exact staleness this check exists to catch.
///
/// A payload with no `base_sha` (e.g. posted before this field existed)
/// can't be verified and is treated as stale.
fn baseline_is_fresh(
    merge_sha: &str,
    commit_count: u64,
    parent_of: &HashMap<&str, &str>,
    payload: &ReportPayload,
) -> bool {
    let Some(tested_base_sha) = payload.base_sha.as_deref() else {
        return false;
    };
    let mut sha = merge_sha;
    for _ in 0..commit_count {
        let Some(&parent_sha) = parent_of.get(sha) else {
            return false;
        };
        sha = parent_sha;
    }
    sha == tested_base_sha
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

/// Default expected author of the sticky report comment: the identity
/// GitHub attributes comments to when posted with the default
/// `GITHUB_TOKEN`. Override this if posting with a different token (a
/// custom bot account, a GitHub App installation, or a PAT).
pub const DEFAULT_EXPECTED_COMMENT_AUTHOR: &str = "github-actions[bot]";

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
    /// Base branch ref name to anchor the baseline commit walk to, taken
    /// from the triggering event rather than resolved live. `None` falls
    /// back to a live lookup of the PR's current base, e.g. outside CI.
    pub base_ref: Option<String>,
    /// Base branch commit SHA to anchor the baseline commit walk to. See
    /// [`Self::base_ref`].
    pub base_sha: Option<String>,
    /// Expected GitHub login of the sticky report comment's author. A
    /// comment is only ever treated as a genuine report -- to patch when
    /// posting, or to read back as a baseline -- when it was posted by
    /// this identity; otherwise anyone who can comment on a PR could
    /// forge a fake report by posting a comment starting with the hidden
    /// marker. See [`DEFAULT_EXPECTED_COMMENT_AUTHOR`].
    pub expected_comment_author: String,
    /// The PR head commit this run tested, taken from the triggering
    /// event. `None` disables the supersession check when posting (e.g.
    /// outside CI).
    ///
    /// Concurrency cancellation in the workflow only cancels *overlapping*
    /// runs; it doesn't stop a manual re-run of an older, already-completed
    /// run after a newer push has been tested and posted. Recording and
    /// checking the tested head directly closes that gap: a run whose
    /// tested head no longer matches the PR's current head knows it has
    /// been superseded and skips posting, rather than overwriting a
    /// fresher report with stale results that share the same base_sha and
    /// would otherwise pass baseline validation undetected.
    pub head_sha: Option<String>,
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
            base_ref: None,
            base_sha: None,
            expected_comment_author: DEFAULT_EXPECTED_COMMENT_AUTHOR.to_string(),
            head_sha: None,
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
            .field("base_ref", &self.base_ref)
            .field("base_sha", &self.base_sha)
            .field("expected_comment_author", &self.expected_comment_author)
            .field("head_sha", &self.head_sha)
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
        if config.expected_comment_author.trim().is_empty() {
            bail!("expected comment author is required");
        }
        config.api_base_url = config.api_base_url.trim_end_matches('/').to_string();
        Ok(Self { config })
    }

    /// Resolves the anchor for the baseline commit walk: the PR's base
    /// branch and the commit to walk back from. Call this before doing any
    /// long-running work (e.g. before running benchmarks) and pass the
    /// result to [`Self::fetch_baseline`] once that work is done.
    ///
    /// Prefers `config.base_ref`/`config.base_sha`, sourced from the
    /// triggering event and fixed for the run, over a live PR lookup:
    /// resolving live is racy even when done up front, since the base
    /// branch can advance between the event firing (what `GITHUB_SHA` was
    /// actually built from) and this call running. The live lookup remains
    /// as a fallback for non-CI use. Returns `None` when the lookback is
    /// zero, so callers don't pay for a PR fetch that would go unused.
    pub async fn resolve_baseline_anchor(&self) -> Result<Option<BaselineAnchor>> {
        if self.config.baseline_commit_lookback == 0 {
            return Ok(None);
        }

        if let (Some(base_ref), Some(base_sha)) = (&self.config.base_ref, &self.config.base_sha) {
            return Ok(Some(BaselineAnchor {
                base_ref: base_ref.clone(),
                base_sha: base_sha.clone(),
            }));
        }

        let client = Client::new();
        let url = format!(
            "{}/repos/{}/pulls/{}",
            self.config.api_base_url, self.config.repo, self.config.pr_number
        );
        let pr = self.get_json(&client, &url, &[], "pull request").await?;
        let base_ref = pr["base"]["ref"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("pull request response did not include base.ref"))?;
        let base_sha = pr["base"]["sha"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("pull request response did not include base.sha"))?;
        Ok(Some(BaselineAnchor { base_ref, base_sha }))
    }

    /// Fetches the baseline report to diff against: the payload embedded in
    /// the sticky report comment of the most recently merged PR on the base
    /// branch. Walks the base branch history from `anchor` commit by
    /// commit, matching each commit to a merged PR by `merge_commit_sha`
    /// rather than GitHub's commit-to-PR association endpoint, which only
    /// reports merged PRs for commits reachable from the repository's
    /// default branch and would otherwise miss every PR merged into a
    /// non-default base. Commits without a matching merged PR (direct
    /// pushes) and PRs without a readable report (failed perf job, predates
    /// the embedded payload) are skipped in favor of an older baseline.
    /// Returns `None` when nothing is found within the lookback window; a
    /// missing baseline only degrades the report to absolute numbers, so
    /// callers can treat errors the same way.
    pub async fn fetch_baseline(&self, anchor: &BaselineAnchor) -> Result<Option<BaselineReport>> {
        let client = Client::new();
        let lookback = self.config.baseline_commit_lookback;
        let commits_url = format!(
            "{}/repos/{}/commits",
            self.config.api_base_url, self.config.repo
        );
        let commits = self
            .get_json_array_paginated(
                &client,
                &commits_url,
                &[("sha", anchor.base_sha.as_str())],
                "base branch commits",
                lookback,
            )
            .await?;

        let pulls_url = format!(
            "{}/repos/{}/pulls",
            self.config.api_base_url, self.config.repo
        );
        // `state=closed` includes closed-but-unmerged PRs alongside merged
        // ones, and `sort=updated` has no reliable relationship to merge
        // order -- a PR merged long ago can resurface at the top of this
        // list from a single new comment, while an unrelated rejected PR
        // can sit there indefinitely. This cap is therefore a bounded
        // best-effort, not an exhaustive search: it can still miss the
        // merged PR for a commit inside the lookback window if enough
        // irrelevant closed PRs crowd it out.
        //
        // TODO: an exhaustive search (page until every commit in the
        // window is accounted for) was tried and reverted: on a
        // repository using rebase-and-merge, every commit but the last in
        // each PR's span can never match any `merge_commit_sha`, which
        // degenerated into paging through the entire closed-PR history on
        // every run. Revisit if this cap turns out to miss baselines in
        // practice.
        let merged_pulls = self
            .get_json_array_paginated(
                &client,
                &pulls_url,
                &[
                    ("base", anchor.base_ref.as_str()),
                    ("state", "closed"),
                    ("sort", "updated"),
                    ("direction", "desc"),
                ],
                "merged pull requests",
                lookback.max(100),
            )
            .await?;

        let parent_of: HashMap<&str, &str> = commits
            .iter()
            .filter_map(|commit| {
                let sha = commit["sha"].as_str()?;
                let parent_sha = commit["parents"][0]["sha"].as_str()?;
                Some((sha, parent_sha))
            })
            .collect();
        let author_of: HashMap<&str, &Value> = commits
            .iter()
            .filter_map(|commit| {
                let sha = commit["sha"].as_str()?;
                let author = commit["commit"].get("author")?;
                Some((sha, author))
            })
            .collect();

        for commit in &commits {
            let Some(sha) = commit["sha"].as_str() else {
                continue;
            };
            let Some(pull) = find_pr_for_merge_commit(&merged_pulls, sha) else {
                continue;
            };
            let Some(pr_number) = pull["number"].as_u64() else {
                continue;
            };
            let comments = self.fetch_comments(&client, pr_number).await?;
            let Some(payload) = find_sticky_comment(
                &comments,
                &self.hidden_marker(),
                &self.config.expected_comment_author,
            )
            .and_then(|comment| comment["body"].as_str())
            .and_then(ReportPayload::extract) else {
                continue;
            };
            // Skip the extra work below when there's nothing to validate
            // against anyway.
            if payload.base_sha.is_none() {
                continue;
            }
            // Cheap and no extra API calls, so check head identity before
            // the base freshness check below: both heads can share the
            // same tested base, so this catches a candidate whose sticky
            // comment was left holding an earlier head's results after a
            // later head's own CI run failed or was cancelled before
            // posting.
            let Some(merged_head_sha) = pull["head"]["sha"].as_str() else {
                continue;
            };
            if !tested_correct_head(payload.head_sha.as_deref(), merged_head_sha) {
                continue;
            }
            // Try the direct parent first: it's an exact sha comparison,
            // so a match is always correct regardless of merge strategy,
            // with no extra API calls. Only fall back to resolving the
            // full landed span -- which relies on an author-based
            // heuristic that could in principle be misled by coincidence
            // -- when this doesn't already settle it.
            let is_fresh = if baseline_is_fresh(sha, 1, &parent_of, &payload) {
                true
            } else {
                let commit_count = self
                    .resolve_landed_commit_count(&client, &author_of, commit, pr_number)
                    .await?;
                baseline_is_fresh(sha, commit_count, &parent_of, &payload)
            };
            if !is_fresh {
                continue;
            }
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
    /// `baseline` is given. The posted comment also embeds the results,
    /// along with the base commit resolved by `anchor`, as a hidden
    /// machine-readable payload; this is what later runs read back as
    /// their baseline, and `anchor`'s base commit is what lets them detect
    /// a candidate whose base branch moved after it was tested (see
    /// [`Self::fetch_baseline`]).
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
        anchor: Option<&BaselineAnchor>,
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
        let payload = ReportPayload::new(
            results,
            anchor.map(|anchor| anchor.base_sha.clone()),
            self.config.head_sha.clone(),
        )
        .embed()?;
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

        // A concurrent push, or a manual re-run of an older completed
        // workflow run, can post after a newer push has already been
        // tested and posted; the workflow's concurrency cancellation only
        // cancels *overlapping* runs, so it doesn't catch either case. If
        // the PR has since moved past the commit this run tested, these
        // results are superseded, and posting them would silently
        // overwrite a fresher report with stale data sharing the same
        // base_sha (undetectable by baseline validation, which doesn't
        // track head identity).
        if let Some(tested_head) = &self.config.head_sha {
            let current_head = self.fetch_pr_head(&client, self.config.pr_number).await?;
            if &current_head != tested_head {
                return Ok(());
            }
        }

        let comments = self.fetch_comments(&client, self.config.pr_number).await?;
        let sticky_comment = find_sticky_comment(
            &comments,
            &hidden_marker,
            &self.config.expected_comment_author,
        );

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
        self.get_json_array(client, &self.comments_url(pr_number), &[], "PR comments")
            .await
    }

    /// Fetches the PR's current head commit sha, live.
    async fn fetch_pr_head(&self, client: &Client, pr_number: u64) -> Result<String> {
        let url = format!(
            "{}/repos/{}/pulls/{pr_number}",
            self.config.api_base_url, self.config.repo
        );
        let pr = self.get_json(client, &url, &[], "pull request").await?;
        pr["head"]["sha"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("pull request response did not include head.sha"))
    }

    /// Returns the number of commits `merge_commit` actually landed on the
    /// base branch: 1 for a squash merge or a standard two-parent merge
    /// commit, regardless of how many source commits the PR had, or the
    /// PR's full source commit count for rebase-and-merge, which replays
    /// every commit individually. See [`merge_looks_rebased`] for how
    /// those two cases are told apart. `author_of` should map each
    /// base-branch commit's sha to its own `commit.author` object, built
    /// from the already-fetched commit history.
    async fn resolve_landed_commit_count(
        &self,
        client: &Client,
        author_of: &HashMap<&str, &Value>,
        merge_commit: &Value,
        pr_number: u64,
    ) -> Result<u64> {
        // A two-parent merge commit is unambiguous: parents[0] is always
        // the base tip immediately before the merge.
        if merge_commit["parents"]
            .as_array()
            .is_some_and(|parents| parents.len() == 2)
        {
            return Ok(1);
        }
        let Some(parent_sha) = merge_commit["parents"][0]["sha"].as_str() else {
            return Ok(1);
        };
        let parent_author = match author_of.get(parent_sha) {
            Some(&author) => author.clone(),
            // The parent falls outside the fetched commit history (the
            // candidate sits at the edge of the lookback window); fetch
            // it directly rather than skip the check.
            None => self.fetch_commit_author(client, parent_sha).await?,
        };
        let pr_commits = self.fetch_pr_commits(client, pr_number).await?;
        if merge_looks_rebased(&parent_author, &pr_commits) {
            Ok(pr_commits.len() as u64)
        } else {
            Ok(1)
        }
    }

    /// Fetches the commits of PR `pr_number`, oldest first.
    ///
    /// TODO: this endpoint paginates at 100 commits per page and this only
    /// fetches the first page, so a PR with more than 100 commits is
    /// treated as if it only had its first 100. Acceptable for now: a PR
    /// that large is already far outside normal usage.
    async fn fetch_pr_commits(&self, client: &Client, pr_number: u64) -> Result<Vec<Value>> {
        let url = format!(
            "{}/repos/{}/pulls/{pr_number}/commits",
            self.config.api_base_url, self.config.repo
        );
        self.get_json_array(client, &url, &[("per_page", "100")], "pull request commits")
            .await
    }

    /// Fetches the `commit.author` object of a single commit.
    async fn fetch_commit_author(&self, client: &Client, sha: &str) -> Result<Value> {
        let url = format!(
            "{}/repos/{}/commits/{sha}",
            self.config.api_base_url, self.config.repo
        );
        let commit = self.get_json(client, &url, &[], "commit").await?;
        let author = commit["commit"]["author"].clone();
        if author.is_null() {
            bail!("commit response did not include author");
        }
        Ok(author)
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

    /// Fetches up to `limit` items from a paginated JSON array endpoint.
    /// `query` should not include `per_page` or `page`: a full page (the
    /// GitHub API's max of 100) is always requested, and further pages are
    /// fetched until `limit` items have been collected or a short page
    /// signals there are no more.
    async fn get_json_array_paginated(
        &self,
        client: &Client,
        url: &str,
        query: &[(&str, &str)],
        what: &str,
        limit: usize,
    ) -> Result<Vec<Value>> {
        const PAGE_SIZE: usize = 100;
        let mut items = Vec::new();
        let mut page = 1u32;
        while items.len() < limit {
            let page_str = page.to_string();
            let mut paged_query = query.to_vec();
            paged_query.push(("per_page", "100"));
            paged_query.push(("page", &page_str));
            let batch = self.get_json_array(client, url, &paged_query, what).await?;
            let batch_len = batch.len();
            items.extend(batch);
            if batch_len < PAGE_SIZE {
                break;
            }
            page += 1;
        }
        items.truncate(limit);
        Ok(items)
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
    fn rejects_a_blank_expected_comment_author() {
        let config = GithubPrReporterConfig {
            repo: "owner/repo".to_string(),
            token: "token".to_string(),
            marker: "marker".to_string(),
            expected_comment_author: "  ".to_string(),
            ..Default::default()
        };
        assert!(GithubPrReporter::new(config).is_err());
    }

    #[test]
    fn finds_sticky_comment_by_marker_and_author() {
        let comments = vec![
            json!({"body": "unrelated comment", "user": {"login": "bot"}}),
            json!({"body": "quoting the `<!-- marker -->` trick", "url": "http://c/2", "user": {"login": "bot"}}),
            json!({"body": "<!-- marker -->\nreport", "url": "http://c/3", "user": {"login": "bot"}}),
            json!({"no_body": true}),
        ];
        let found = find_sticky_comment(&comments, "<!-- marker -->", "bot").unwrap();
        assert_eq!(found["url"], "http://c/3");
        assert!(find_sticky_comment(&comments, "<!-- other -->", "bot").is_none());
    }

    #[test]
    fn ignores_marker_match_from_an_untrusted_author() {
        // Anyone who can comment on a PR could post a body starting with
        // the marker; without checking the author, this would be
        // indistinguishable from a genuine report.
        let comments = vec![
            json!({"body": "<!-- marker -->\nforged report", "url": "http://c/1", "user": {"login": "attacker"}}),
        ];
        assert!(find_sticky_comment(&comments, "<!-- marker -->", "bot").is_none());
    }

    #[test]
    fn finds_pr_by_merge_commit_sha() {
        let merged_pulls = vec![
            json!({"number": 1, "merged_at": null, "merge_commit_sha": "abc123"}),
            json!({"number": 2, "merged_at": "2026-07-01T00:00:00Z", "merge_commit_sha": "def456"}),
            json!({"number": 3, "merged_at": "2026-07-01T00:00:00Z", "merge_commit_sha": "abc123"}),
        ];
        assert_eq!(
            find_pr_for_merge_commit(&merged_pulls, "abc123")
                .and_then(|pull| pull["number"].as_u64()),
            Some(3)
        );
        assert_eq!(
            find_pr_for_merge_commit(&merged_pulls, "def456")
                .and_then(|pull| pull["number"].as_u64()),
            Some(2)
        );
        assert!(find_pr_for_merge_commit(&merged_pulls, "missing").is_none());
    }

    #[test]
    fn tested_correct_head_matches_recorded_head() {
        assert!(tested_correct_head(Some("head1"), "head1"));
    }

    #[test]
    fn tested_correct_head_rejects_a_mismatched_head() {
        // The sticky comment held an earlier head's results because a
        // later head's own CI run failed or was cancelled before posting.
        assert!(!tested_correct_head(Some("head1"), "head2"));
    }

    #[test]
    fn tested_correct_head_rejects_a_missing_head() {
        assert!(!tested_correct_head(None, "head1"));
    }

    fn payload_with_base_sha(base_sha: Option<&str>) -> ReportPayload {
        ReportPayload {
            base_sha: base_sha.map(str::to_string),
            head_sha: None,
            zkvms: Vec::new(),
        }
    }

    fn pr_commit_with_author(name: &str, date: &str) -> Value {
        json!({"commit": {"author": {"name": name, "email": "a@example.com", "date": date}}})
    }

    #[test]
    fn merge_looks_rebased_when_parent_author_matches_second_to_last_commit() {
        let pr_commits = vec![
            pr_commit_with_author("alice", "2026-01-01T00:00:00Z"),
            pr_commit_with_author("alice", "2026-01-02T00:00:00Z"),
            pr_commit_with_author("alice", "2026-01-03T00:00:00Z"),
        ];
        let parent_author =
            pr_commit_with_author("alice", "2026-01-02T00:00:00Z")["commit"]["author"].clone();
        assert!(merge_looks_rebased(&parent_author, &pr_commits));
    }

    #[test]
    fn merge_does_not_look_rebased_when_parent_author_predates_the_pr() {
        // A squash (or standard merge) commit's parent is the base tip
        // from before the PR touched anything, authored by whoever
        // committed to the base branch at that point.
        let pr_commits = vec![
            pr_commit_with_author("alice", "2026-01-01T00:00:00Z"),
            pr_commit_with_author("alice", "2026-01-02T00:00:00Z"),
        ];
        let parent_author =
            pr_commit_with_author("bob", "2025-06-01T00:00:00Z")["commit"]["author"].clone();
        assert!(!merge_looks_rebased(&parent_author, &pr_commits));
    }

    #[test]
    fn merge_does_not_look_rebased_for_a_single_commit_pr() {
        // Squash and rebase are indistinguishable for a single-commit PR
        // -- both land as exactly one commit -- so this is never "rebased".
        let pr_commits = vec![pr_commit_with_author("alice", "2026-01-01T00:00:00Z")];
        let parent_author =
            pr_commit_with_author("alice", "2026-01-01T00:00:00Z")["commit"]["author"].clone();
        assert!(!merge_looks_rebased(&parent_author, &pr_commits));
    }

    #[test]
    fn baseline_is_fresh_when_tested_base_matches_merge_parent() {
        let parent_of = HashMap::from([("merge1", "base1")]);
        let payload = payload_with_base_sha(Some("base1"));
        assert!(baseline_is_fresh("merge1", 1, &parent_of, &payload));
    }

    #[test]
    fn baseline_is_fresh_across_a_multi_commit_rebase_span() {
        // Rebase-and-merge replays each of the PR's commits individually;
        // the tested base is several hops back through the PR's own
        // commits, not the merge commit's direct parent.
        let parent_of = HashMap::from([
            ("rebased3", "rebased2"),
            ("rebased2", "rebased1"),
            ("rebased1", "base1"),
        ]);
        let payload = payload_with_base_sha(Some("base1"));
        assert!(baseline_is_fresh("rebased3", 3, &parent_of, &payload));
    }

    #[test]
    fn baseline_is_stale_when_base_advanced_before_merge() {
        // The candidate was last tested against `base1`, but by the time it
        // merged the base branch had moved on to `base2`.
        let parent_of = HashMap::from([("merge1", "base2")]);
        let payload = payload_with_base_sha(Some("base1"));
        assert!(!baseline_is_fresh("merge1", 1, &parent_of, &payload));
    }

    #[test]
    fn baseline_is_stale_when_an_older_base_sha_is_reachable_further_back() {
        // The candidate (a single-commit PR) was tested against `base1`,
        // but an unrelated PR advanced the base to `base2` before the
        // candidate merged, so its merge parent is `base2`, not `base1`.
        // `base1` is still reachable further up the chain -- as ordinary
        // history, not as part of this candidate's own span -- and must
        // not be mistaken for a match.
        let parent_of = HashMap::from([("merge1", "base2"), ("base2", "base1")]);
        let payload = payload_with_base_sha(Some("base1"));
        assert!(!baseline_is_fresh("merge1", 1, &parent_of, &payload));
    }

    #[test]
    fn baseline_is_stale_without_a_tested_base_sha() {
        let parent_of = HashMap::from([("merge1", "base1")]);
        let payload = payload_with_base_sha(None);
        assert!(!baseline_is_fresh("merge1", 1, &parent_of, &payload));
    }

    #[test]
    fn baseline_is_stale_without_commit_parents() {
        let parent_of = HashMap::new();
        let payload = payload_with_base_sha(Some("base1"));
        assert!(!baseline_is_fresh("merge1", 1, &parent_of, &payload));
    }
}
