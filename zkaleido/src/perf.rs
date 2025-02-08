use std::time::{Duration, Instant};

use serde::Serialize;
/// A proof report containing a performance stats about proof generation.
#[derive(Debug, Clone)]
pub struct PerfReport {
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

/// Executes the provided closure once and measures the time it takes to complete.
pub fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T, Duration) {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}

/// A proof report containing a performance stats about proof generation.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ProofReport {
    /// The duration of the proving time in seconds.
    pub prove_duration: f64,
    /// The size of the proof.
    pub proof_size: usize,
    /// The duration of the verification time in seconds.
    pub verify_duration: f64,
    /// The speed in KHz.
    pub speed: f64,
}

/// Performace report
#[derive(Debug, Serialize, Default)]
pub struct PerformanceReport {
    /// The number of shards.
    pub shards: usize,
    /// The reported number of cycles.
    ///
    /// Note that this number may vary based on the zkVM.
    pub cycles: u64,
    /// The duration for execution in seconds
    pub execution_duration: f64,

    /// [ProofReport] for [Core](crate::proof::ProofType::Core) proof
    pub core_proof_report: Option<ProofReport>,

    /// [ProofReport] for [Compressed](crate::proof::ProofType::Compressed) proof
    pub compressed_proof_report: Option<ProofReport>,

    /// [ProofReport] for [Groth16](crate::proof::ProofType::Groth16) proof
    pub groth16_proof_report: Option<ProofReport>,

    /// End to end prove duration for the given proof
    pub e2e_prove_duration: f64,

    /// End to end proving speed
    pub e2e_prove_speed: f64,
}

impl PerformanceReport {
    /// Genereates new performance report
    pub fn new(
        shards: usize,
        cycles: u64,
        execution_duration: f64,
        core_proof_report: Option<ProofReport>,
        compressed_proof_report: Option<ProofReport>,
        groth16_proof_report: Option<ProofReport>,
    ) -> Self {
        let e2e_prove_duration = core_proof_report.clone().unwrap_or_default().prove_duration
            + compressed_proof_report
                .clone()
                .unwrap_or_default()
                .prove_duration
            + groth16_proof_report
                .clone()
                .unwrap_or_default()
                .prove_duration;

        let e2e_prove_speed = cycles as f64 / e2e_prove_duration / 1_000.0;

        Self {
            shards,
            cycles,
            execution_duration,
            core_proof_report,
            compressed_proof_report,
            groth16_proof_report,
            e2e_prove_duration,
            e2e_prove_speed,
        }
    }
}
