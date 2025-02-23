use fibonacci::FibProgram;
use fibonacci_composition::{FibCompositionInput, FibCompositionProgram};
use zkaleido::{
    AggregationInput, PerformanceReport, ZkVmHost, ZkVmHostPerf, ZkVmProgram, ZkVmProgramPerf,
};

fn fib_composition_prover_perf_report(
    fib_host: &impl ZkVmHost,
    fib_composition_host: &impl ZkVmHostPerf,
) -> PerformanceReport {
    let input = 5;
    let receipt = FibProgram::prove(&input, fib_host).unwrap();
    let vk = fib_host.get_verification_key();
    let fib_proof_with_vk = AggregationInput::new(receipt, vk);
    let fib_vk_commitment = fib_host.get_verification_key_commitment();
    let input = FibCompositionInput {
        fib_proof_with_vk,
        fib_vk_commitment,
    };
    FibCompositionProgram::perf_report(&input, fib_composition_host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_fib_composition_report() -> PerformanceReport {
    use zkaleido_sp1_adapter::SP1Host;
    use zkaleido_sp1_artifacts::{FIBONACCI_COMPOSITION_ELF, FIBONACCI_ELF};
    let fib_host = SP1Host::init(FIBONACCI_ELF);
    let fib_composition_host = SP1Host::init(FIBONACCI_COMPOSITION_ELF);
    fib_composition_prover_perf_report(&fib_host, &fib_composition_host)
}

#[cfg(feature = "risc0")]
pub fn risc0_fib_composition_report() -> PerformanceReport {
    use zkaleido_risc0_adapter::Risc0Host;
    use zkaleido_risc0_artifacts::{
        GUEST_RISC0_FIBONACCI_COMPOSITION_ELF, GUEST_RISC0_FIBONACCI_ELF,
    };
    let fib_host = Risc0Host::init(GUEST_RISC0_FIBONACCI_ELF);
    let fib_composition_host = Risc0Host::init(GUEST_RISC0_FIBONACCI_COMPOSITION_ELF);
    fib_composition_prover_perf_report(&fib_host, &fib_composition_host)
}
