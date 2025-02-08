use std::time::{Duration, Instant};

use serde::Serialize;
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

/// The performance report of a zkVM on a program.
///
/// Adapted from [zkvm-perf](https://github.dev/succinctlabs/zkvm-perf/blob/main/eval/src/main.rs)
#[derive(Debug, Serialize, Default)]
pub struct PerformanceReport {
    /// The number of shards.
    pub shards: usize,
    /// The reported number of cycles.
    ///
    /// Note that this number may vary based on the zkVM.
    pub cycles: u64,
    /// The reported speed in cycles per second.
    pub speed: f64,
    /// The reported duration of the prover in seconds.
    pub prove_duration: f64,

    /// The reported duration of the core proving time in seconds.
    pub core_prove_duration: f64,
    /// The reported duration of the verifier in seconds.
    pub core_verify_duration: f64,
    /// The size of the core proof.
    pub core_proof_size: usize,
    /// The speed of the core proving time in KHz.
    pub core_khz: f64,

    /// The reported duration of the recursive proving time in seconds.
    pub compress_prove_duration: f64,
    /// The reported duration of the verifier in seconds.
    pub compress_verify_duration: f64,
    /// The size of the recursive proof in bytes.
    pub compress_proof_size: usize,

    /// The reported duration of the shrink proving time in seconds.
    pub shrink_prove_duration: f64,
    /// The reported duration of the wrap proving time in seconds.
    pub wrap_prove_duration: f64,
    /// The reported duration of the groth16 proving time in seconds.
    pub groth16_prove_duration: f64,

    /// The overall speed in KHz.
    pub overall_khz: f64,
}

/// Executes the provided closure once and measures the time it takes to complete.
pub fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T, Duration) {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}
