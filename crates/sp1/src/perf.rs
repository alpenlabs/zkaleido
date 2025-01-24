use std::time::Instant;

use sp1_sdk::ProverClient;
use strata_zkvm::{ProofReport, ProofType, ZkVmHost, ZkVmHostPerf, ZkVmInputBuilder, ZkVmResult};

use crate::SP1Host;

impl ZkVmHostPerf for SP1Host {
    fn perf_report<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
        report_name: String,
    ) -> ZkVmResult<ProofReport> {
        let client = ProverClient::from_env();

        let start = Instant::now();
        if std::env::var("ZKVM_PROFILING_DUMP")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            std::env::set_var("TRACE_FILE", format!("{}.sp1.trace", report_name));
        }

        let (_, report) = client.execute(self.get_elf(), &input).run().unwrap();
        let execution_time = start.elapsed().as_millis();

        let _ = self.prove(input, proof_type)?;
        let proving_time = start.elapsed().as_millis();

        Ok(ProofReport {
            name: report_name,
            cycles: report.total_instruction_count(),
            execution_time,
            proving_time,
        })
    }
}
