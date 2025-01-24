use crate::{ProofType, ZkVmHost, ZkVmInputBuilder, ZkVmProver, ZkVmResult};

/// A proof report containing a performance stats about proof generation.
#[derive(Debug, Clone)]
pub struct ProofReport {
    pub name: String,
    pub cycles: u64,
    pub execution_time: u128,
    pub proving_time: u128,
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
    fn perf_report<'a, H>(input: &'a Self::Input, host: &H) -> ZkVmResult<ProofReport>
    where
        H: ZkVmHostPerf,
        H::Input<'a>: ZkVmInputBuilder<'a>,
    {
        // Prepare the input using the host's input builder.
        let zkvm_input = Self::prepare_input::<H::Input<'a>>(input)?;

        // Get the proof report
        // TODO: Ideally we should not send name of the prover to the host
        host.perf_report(zkvm_input, Self::proof_type(), Self::name())
    }
}
