use sp1_sdk::ProverClient;
use zkaleido::{time_operation, PerformanceReport, ZkVmHost, ZkVmHostPerf};

use crate::SP1Host;

impl ZkVmHostPerf for SP1Host {
    fn perf_report<'a>(
        &self,
        input: <Self::Input<'a> as zkaleido::ZkVmInputBuilder<'a>>::Input,
    ) -> PerformanceReport {
        let client = ProverClient::from_env();

        let (_, execution_duration) =
            time_operation(|| client.execute(self.get_elf(), &input).run().unwrap());
    }
}
