use fibonacci::program::FibProgram;
use fibonacci_composition::program::{FibCompositionInput, FibCompositionProgram};
use zkaleido::{AggregationInput, ExecutionSummary, ZkVmHost, ZkVmProgram};

fn fib_composition_execution_report(
    fib_host: &impl ZkVmHost,
    fib_composition_host: &impl ZkVmHost,
) -> (String, ExecutionSummary) {
    let input = 5;
    let receipt = FibProgram::prove(&input, fib_host).unwrap();
    let vk = fib_host.vk();
    let fib_proof_with_vk = AggregationInput::new(receipt, vk);
    let fib_program_id = fib_host.program_id();
    let input = FibCompositionInput {
        fib_proof_with_vk,
        fib_program_id,
    };
    let summary = FibCompositionProgram::execute(&input, fib_composition_host).unwrap();
    (FibCompositionProgram::name(), summary)
}

#[cfg(feature = "sp1")]
pub async fn sp1_fib_composition_report() -> (String, ExecutionSummary) {
    use zkaleido_sp1_artifacts::{FIBONACCI_COMPOSITION_ELF, FIBONACCI_ELF};
    use zkaleido_sp1_host::SP1Host;
    let fib_host = SP1Host::init(&FIBONACCI_ELF).await;
    let fib_composition_host = SP1Host::init(&FIBONACCI_COMPOSITION_ELF).await;
    fib_composition_execution_report(&fib_host, &fib_composition_host)
}

#[cfg(feature = "risc0")]
pub async fn risc0_fib_composition_report() -> (String, ExecutionSummary) {
    use zkaleido_risc0_artifacts::{
        GUEST_RISC0_FIBONACCI_COMPOSITION_ELF, GUEST_RISC0_FIBONACCI_ELF,
    };
    use zkaleido_risc0_host::Risc0Host;
    let fib_host = Risc0Host::init(GUEST_RISC0_FIBONACCI_ELF);
    let fib_composition_host = Risc0Host::init(GUEST_RISC0_FIBONACCI_COMPOSITION_ELF);
    fib_composition_execution_report(&fib_host, &fib_composition_host)
}
