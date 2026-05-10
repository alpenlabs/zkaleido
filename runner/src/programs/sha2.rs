use sha2_chain::program::ShaChainProgram;
use zkaleido::{ExecutionSummary, ZkVmHost, ZkVmProgram};

fn sha2_execution_report(host: &impl ZkVmHost) -> (String, ExecutionSummary) {
    let input = 5;
    let summary = ShaChainProgram::execute(&input, host).unwrap();
    (ShaChainProgram::name(), summary)
}

#[cfg(feature = "sp1")]
pub fn sp1_sha_report() -> (String, ExecutionSummary) {
    use zkaleido_sp1_artifacts::SHA2_CHAIN_ELF;
    use zkaleido_sp1_host::SP1Host;
    let host = SP1Host::init(&SHA2_CHAIN_ELF);
    sha2_execution_report(&host)
}

#[cfg(feature = "risc0")]
pub fn risc0_sha_report() -> (String, ExecutionSummary) {
    use zkaleido_risc0_artifacts::GUEST_RISC0_SHA2_CHAIN_ELF;
    use zkaleido_risc0_host::Risc0Host;
    let host = Risc0Host::init(GUEST_RISC0_SHA2_CHAIN_ELF);
    sha2_execution_report(&host)
}
