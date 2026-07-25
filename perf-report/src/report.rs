use zkaleido::{ExecutionSummary, ZkVm};

/// Execution results of a single guest program.
#[derive(Debug, Clone)]
pub struct ProgramResult {
    /// Name of the guest program.
    pub name: String,
    /// Execution summary produced by the host.
    pub summary: ExecutionSummary,
}

/// Execution results of a set of guest programs on one zkVM host.
#[derive(Debug, Clone)]
pub struct ZkVmResults {
    /// The zkVM that produced the results.
    pub zkvm: ZkVm,
    /// Per-program execution results.
    pub results: Vec<ProgramResult>,
}

impl ZkVmResults {
    /// Creates results for `zkvm` from `(program name, summary)` pairs.
    pub fn new(zkvm: ZkVm, results: impl IntoIterator<Item = (String, ExecutionSummary)>) -> Self {
        Self {
            zkvm,
            results: results
                .into_iter()
                .map(|(name, summary)| ProgramResult { name, summary })
                .collect(),
        }
    }
}
