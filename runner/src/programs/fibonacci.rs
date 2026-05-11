use fibonacci::program::FibProgram;
use zkaleido::{ExecutionSummary, ZkVmHost, ZkVmProgram};

fn fib_execution_report(host: &impl ZkVmHost) -> (String, ExecutionSummary) {
    let input = 5;
    let summary = FibProgram::execute(&input, host).unwrap();
    (FibProgram::name(), summary)
}

#[cfg(feature = "sp1")]
pub async fn sp1_fib_report() -> (String, ExecutionSummary) {
    use zkaleido_sp1_artifacts::FIBONACCI_ELF;
    use zkaleido_sp1_host::SP1Host;
    let host = SP1Host::init(&FIBONACCI_ELF).await;
    fib_execution_report(&host)
}

#[cfg(feature = "risc0")]
pub async fn risc0_fib_report() -> (String, ExecutionSummary) {
    use zkaleido_risc0_artifacts::GUEST_RISC0_FIBONACCI_ELF;
    use zkaleido_risc0_host::Risc0Host;
    let host = Risc0Host::init(GUEST_RISC0_FIBONACCI_ELF);
    fib_execution_report(&host)
}
