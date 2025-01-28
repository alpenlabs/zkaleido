/// A proof report containing a performance stats about proof generation.
#[derive(Debug, Clone)]
pub struct ProofReport {
    /// A human-readable name identifying the prover or proof process.
    pub name: String,
    /// The number of cycles (or execution steps) that the ZkVM consumed to run the computation.
    pub cycles: u64,
    /// The total time (in milliseconds) it took to execute the computation within the ZkVM.
    pub execution_time: u128,
    /// The total time (in milliseconds) for the entire proving process, which includes both
    /// execution and proof generation phases.
    pub proving_time: u128,
}
