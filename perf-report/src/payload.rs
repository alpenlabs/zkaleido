use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::report::ZkVmResults;

/// Opening of the hidden HTML comment that embeds the machine-readable
/// results in a posted report.
const DATA_MARKER_PREFIX: &str = "<!-- zkaleido-perf-data:";

/// Closing of the hidden HTML comment opened by [`DATA_MARKER_PREFIX`].
const DATA_MARKER_SUFFIX: &str = "-->";

/// Machine-readable execution results embedded in a posted report comment.
///
/// A later run reads this back from the baseline PR's comment to diff
/// against, so the shape must stay backward-compatible; a payload that
/// fails to decode is treated as "no baseline".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPayload {
    /// The base branch commit this report was actually tested against
    /// (from the resolved baseline anchor), `None` if the anchor couldn't
    /// be resolved. A later baseline walk uses this to detect a candidate
    /// whose base branch advanced after it was last benchmarked but before
    /// it merged: the payload would then describe a tree that never
    /// existed in the branch's history, silently attributing the base's
    /// intervening changes to whichever PR is compared against it next.
    /// `#[serde(default)]` so a payload posted before this field existed
    /// still decodes, as `None`.
    #[serde(default)]
    pub base_sha: Option<String>,
    /// The PR head commit this report was actually tested against, `None`
    /// if unavailable (e.g. outside CI). A later baseline walk uses this
    /// to detect a candidate whose CI run posted successfully for an
    /// earlier head, then failed or was cancelled for a later head before
    /// it could post -- leaving the sticky comment describing a commit
    /// that isn't what the PR actually merged. The base-only freshness
    /// check can't catch this, since both heads can share the same tested
    /// base. `#[serde(default)]` so a payload posted before this field
    /// existed still decodes, as `None`.
    #[serde(default)]
    pub head_sha: Option<String>,
    /// Per-zkVM results.
    pub zkvms: Vec<ZkVmPayload>,
}

/// Execution results of one zkVM, as embedded in a report comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkVmPayload {
    /// Display name of the zkVM, e.g. `SP1`.
    pub zkvm: String,
    /// Per-program execution results.
    pub results: Vec<ProgramPayload>,
}

/// Execution results of one guest program, as embedded in a report comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramPayload {
    /// Name of the guest program.
    pub name: String,
    /// The number of cycles consumed during execution.
    pub cycles: u64,
    /// Gas consumed during execution, if applicable.
    pub gas: Option<u64>,
}

impl ReportPayload {
    /// Renders the payload as a hidden HTML comment for embedding in a
    /// report comment body.
    pub(crate) fn embed(&self) -> Result<String> {
        let json = serde_json::to_string(self).context("failed to serialize report payload")?;
        Ok(format!("{DATA_MARKER_PREFIX} {json} {DATA_MARKER_SUFFIX}"))
    }

    /// Extracts the payload embedded in a comment body, `None` if the body
    /// has no payload or it does not decode.
    pub fn extract(body: &str) -> Option<Self> {
        let start = body.find(DATA_MARKER_PREFIX)? + DATA_MARKER_PREFIX.len();
        let end = body[start..].find(DATA_MARKER_SUFFIX)? + start;
        serde_json::from_str(body[start..end].trim()).ok()
    }

    /// Returns the results of the zkVM with the given display name.
    pub fn zkvm(&self, zkvm: &str) -> Option<&ZkVmPayload> {
        self.zkvms.iter().find(|entry| entry.zkvm == zkvm)
    }
}

impl ZkVmPayload {
    /// Returns the results of the program with the given name.
    pub fn program(&self, name: &str) -> Option<&ProgramPayload> {
        self.results.iter().find(|entry| entry.name == name)
    }
}

impl ReportPayload {
    /// Builds the payload embedded in a posted report. `base_sha` should be
    /// the base commit resolved by the run's [`BaselineAnchor`], `None` if
    /// no anchor was resolved (lookup disabled or failed); `head_sha`
    /// should be the PR head commit this run tested, `None` outside CI.
    /// Either being `None` makes this payload unusable as a future
    /// baseline since there is nothing to validate it against.
    ///
    /// [`BaselineAnchor`]: crate::BaselineAnchor
    pub fn new(
        results: &[ZkVmResults],
        base_sha: Option<String>,
        head_sha: Option<String>,
    ) -> Self {
        Self {
            base_sha,
            head_sha,
            zkvms: results
                .iter()
                .map(|zkvm_results| ZkVmPayload {
                    zkvm: zkvm_results.zkvm.to_string(),
                    results: zkvm_results
                        .results
                        .iter()
                        .map(|program| ProgramPayload {
                            name: program.name.clone(),
                            cycles: program.summary.cycles(),
                            gas: program.summary.gas(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> ReportPayload {
        ReportPayload {
            base_sha: Some("abc123".to_string()),
            head_sha: Some("head123".to_string()),
            zkvms: vec![ZkVmPayload {
                zkvm: "SP1".to_string(),
                results: vec![
                    ProgramPayload {
                        name: "fibonacci".to_string(),
                        cycles: 12_345,
                        gas: Some(678),
                    },
                    ProgramPayload {
                        name: "sha2-chain".to_string(),
                        cycles: 99,
                        gas: None,
                    },
                ],
            }],
        }
    }

    #[test]
    fn embed_extract_round_trips() {
        let payload = sample_payload();
        let body = format!("some report text\n{}\nmore text", payload.embed().unwrap());

        let extracted = ReportPayload::extract(&body).expect("payload should extract");
        let program = extracted.zkvm("SP1").unwrap().program("fibonacci").unwrap();
        assert_eq!(program.cycles, 12_345);
        assert_eq!(program.gas, Some(678));
        let program = extracted
            .zkvm("SP1")
            .unwrap()
            .program("sha2-chain")
            .unwrap();
        assert_eq!(program.gas, None);
    }

    #[test]
    fn extract_returns_none_without_payload() {
        assert!(ReportPayload::extract("just a comment").is_none());
        assert!(ReportPayload::extract("<!-- zkaleido-perf-data: not json -->").is_none());
    }

    #[test]
    fn lookups_return_none_for_unknown_names() {
        let payload = sample_payload();
        assert!(payload.zkvm("Risc0").is_none());
        assert!(payload.zkvm("SP1").unwrap().program("unknown").is_none());
    }
}
