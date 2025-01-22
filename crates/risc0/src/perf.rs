use risc0_zkvm::default_executor;
use strata_zkvm::{ProofReport, ProofType, ZkVmHost, ZkVmHostPerf, ZkVmInputBuilder, ZkVmResult};

use crate::Risc0Host;

impl ZkVmHostPerf for Risc0Host {
    fn perf_report<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        _proof_type: ProofType,
        report_name: String,
    ) -> ZkVmResult<ProofReport> {
        let executor = default_executor();

        std::env::set_var("RISC0_PPROF_OUT", format!("{}.risc0.trace", report_name));

        // TODO: handle error
        let session_info = executor.execute(input, self.get_elf()).unwrap();

        Ok(ProofReport {
            cycles: session_info.cycles(),
            report_name,
        })
    }
}
