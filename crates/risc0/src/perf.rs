use std::time::Instant;

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

        let start = Instant::now();
        if std::env::var("ZKVM_PROFILING_DUMP")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            std::env::set_var("RISC0_PPROF_OUT", format!("{}.risc0.trace", report_name));
        }

        // TODO: handle error
        let session_info = executor.execute(input, self.get_elf()).unwrap();
        let execution_time = start.elapsed().as_millis();

        // let _ = self.prove(input, proof_type)?;
        let proving_time = start.elapsed().as_millis();

        Ok(ProofReport {
            cycles: session_info.cycles(),
            name: report_name,
            execution_time,
            proving_time,
        })
    }
}
