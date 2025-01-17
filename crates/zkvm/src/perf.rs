use crate::{ProofType, ZkVmHost, ZkVmInputBuilder, ZkVmProver, ZkVmResult};

/// A proof report containing a performance stats about proof generation.
#[derive(Debug, Clone)]
pub struct ProofReport {
    pub cycles: u64,
    pub report_name: String,
}

/// An extension trait that supports performance report for [`ZkVmHost`].
pub trait ZkVmHostPerf: ZkVmHost {
    /// Generates a performance report for the given input and proof type.
    fn perf_report<'a>(
        &self,
        input: <Self::Input<'a> as ZkVmInputBuilder<'a>>::Input,
        proof_type: ProofType,
        report_name: String,
    ) -> ZkVmResult<ProofReport>;
}

pub trait ZkVmProverPerf: ZkVmProver {
    fn perf_report<'a, H>(
        input: &'a Self::Input,
        host: &H,
        report_name: String,
    ) -> ZkVmResult<ProofReport>
    where
        H: ZkVmHostPerf,
        H::Input<'a>: ZkVmInputBuilder<'a>,
    {
        // Prepare the input using the host's input builder.
        let zkvm_input = Self::prepare_input::<H::Input<'a>>(input)?;

        // Get the proof report
        host.perf_report(zkvm_input, Self::proof_type(), report_name)
    }
}
