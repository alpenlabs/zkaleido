use fibonacci::FibProver;
use fibonacci_composition::FibCompositionProver;
use zkaleido::{AggregationInput, ProofReport, ZkVmHost, ZkVmProver};

fn fib_composition_prover_perf_report(
    fib_host: &impl ZkVmHost,
    fib_composition_host: &impl ZkVmHost,
) -> ProofReport {
    let input = 5;
    let receipt = FibProver::prove(&input, fib_host).unwrap();
    println!("{:?}", receipt);
    let vk = fib_host.get_verification_key();
    let input = AggregationInput::new(receipt, vk);
    FibCompositionProver::perf_report(&input, fib_composition_host).unwrap()
}

#[cfg(feature = "sp1")]
pub fn sp1_fib_composition_report() -> ProofReport {
    use zkaleido_sp1_adapter::SP1Host;
    use zkaleido_sp1_artifacts::{FIBONACCI_COMPOSITION_ELF, FIBONACCI_ELF};
    let fib_host = SP1Host::init(FIBONACCI_ELF);
    let fib_composition_host = SP1Host::init(FIBONACCI_COMPOSITION_ELF);
    fib_composition_prover_perf_report(&fib_host, &fib_composition_host)
}

#[cfg(feature = "risc0")]
pub fn risc0_fib_composition_report() -> ProofReport {
    use zkaleido_risc0_adapter::Risc0Host;
    use zkaleido_risc0_artifacts::{
        GUEST_RISC0_FIBONACCI_COMPOSITION_ELF, GUEST_RISC0_FIBONACCI_ELF,
    };
    let fib_host = Risc0Host::init(GUEST_RISC0_FIBONACCI_ELF);
    let fib_composition_host = Risc0Host::init(GUEST_RISC0_FIBONACCI_COMPOSITION_ELF);
    fib_composition_prover_perf_report(&fib_host, &fib_composition_host)
}
