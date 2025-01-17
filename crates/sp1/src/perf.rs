use crate::SP1Host;
use sp1_sdk::ProverClient;
use strata_zkvm::{ProofReport, ProofType, ZkVmHost, ZkVmHostPerf, ZkVmInputBuilder, ZkVmResult};

impl ZkVmHostPerf for SP1Host {
    fn perf_report<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        _proof_type: ProofType,
        report_name: String,
    ) -> ZkVmResult<ProofReport> {
        let client = ProverClient::from_env();

        std::env::set_var("TRACE_FILE", format!("{}.trace", report_name));

        let (_, report) = client.execute(self.get_elf(), &input).run().unwrap();

        Ok(ProofReport {
            cycles: report.total_instruction_count(),
            report_name,
        })
    }
}
