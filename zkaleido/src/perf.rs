use std::time::{Duration, Instant};

use serde::Serialize;

/// A proof report containing a performance stats about proof generation.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ProofMetrics {
    /// The duration of the proving time in seconds.
    pub prove_duration: f64,
    /// The size of the proof.
    pub proof_size: usize,
    /// The duration of the verification time in seconds.
    pub verify_duration: f64,
    /// The speed in KHz.
    pub speed: f64,
}

/// Performance report
#[derive(Debug, Clone, Serialize, Default)]
pub struct PerformanceReport {
    /// A human-readable name identifying the prover or proof process.
    pub name: String,

    /// The number of shards.
    pub shards: usize,
    /// The reported number of cycles.
    ///
    /// Note that this number may vary based on the zkVM.
    pub cycles: u64,

    /// The duration for execution in seconds
    pub execution_duration: f64,

    /// [ProofMetrics] for [`Core`](crate::proof::ProofType::Core) proof
    pub core_proof_metrics: Option<ProofMetrics>,

    /// [`ProofMetrics`] for [`Compressed`](crate::proof::ProofType::Compressed) proof
    pub compressed_proof_metrics: Option<ProofMetrics>,

    /// [`ProofMetrics`] for [`Groth16`](crate::proof::ProofType::Groth16) proof
    pub groth16_proof_metrics: Option<ProofMetrics>,

    /// End to end prove duration for the given proof
    pub e2e_prove_duration: f64,

    /// End to end proving speed
    pub e2e_prove_speed: f64,

    /// Returns if the performance report was generated with success
    pub success: bool,
}

impl PerformanceReport {
    /// Generates new performance report based on the given proof metrics
    pub fn new(
        shards: usize,
        cycles: u64,
        execution_duration: f64,
        core_proof_report: Option<ProofMetrics>,
        compressed_proof_report: Option<ProofMetrics>,
        groth16_proof_report: Option<ProofMetrics>,
    ) -> Self {
        let e2e_prove_duration = execution_duration
            + core_proof_report.clone().unwrap_or_default().prove_duration
            + compressed_proof_report
                .clone()
                .unwrap_or_default()
                .prove_duration
            + groth16_proof_report
                .clone()
                .unwrap_or_default()
                .prove_duration;

        let e2e_prove_speed = cycles as f64 / e2e_prove_duration / 1_000.0;

        // This is expected to be overwritten by the Prover.
        let name = "".to_string();

        Self {
            name,
            shards,
            cycles,
            execution_duration,
            core_proof_metrics: core_proof_report,
            compressed_proof_metrics: compressed_proof_report,
            groth16_proof_metrics: groth16_proof_report,
            e2e_prove_duration,
            e2e_prove_speed,
            success: true,
        }
    }
}

/// Executes the provided closure once and measures the time it takes to complete.
pub fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T, Duration) {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}
