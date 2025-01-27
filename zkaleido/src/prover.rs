use std::time::Instant;

use crate::{
    host::ZkVmHost, input::ZkVmInputBuilder, ProofReceipt, ProofReport, ProofType, PublicValues,
    ZkVmInputResult, ZkVmResult,
};

pub trait ZkVmProver {
    type Input;
    type Output;

    fn name() -> String;

    fn proof_type() -> ProofType;

    /// Prepares the input for the zkVM.
    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: ZkVmInputBuilder<'a>;

    /// Processes the [`PublicValues`] to produce the final output.
    fn process_output<H>(public_values: &PublicValues) -> ZkVmResult<Self::Output>
    where
        H: ZkVmHost;

    /// Proves the computation using any zkVM host.
    fn prove<'a, H>(input: &'a Self::Input, host: &H) -> ZkVmResult<ProofReceipt>
    where
        H: ZkVmHost,
        H::Input<'a>: ZkVmInputBuilder<'a>,
    {
        // Prepare the input using the host's input builder.
        let zkvm_input = Self::prepare_input::<H::Input<'a>>(input)?;

        // Use the host to prove.
        let receipt = host.prove(zkvm_input, Self::proof_type())?;

        // Process output to see if we are getting the expected type.
        let _ = Self::process_output::<H>(receipt.public_values())?;

        // Dump the proof to file if flag is enabled
        if std::env::var("ZKVM_PROOF_DUMP")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            let receipt_name = format!("{}_{:?}.proof", Self::name(), host);
            receipt.save(receipt_name).unwrap();
        }

        Ok(receipt)
    }

    /// Generates the proof report using any zkVM host.
    fn perf_report<'a, H>(input: &'a Self::Input, host: &H) -> ZkVmResult<ProofReport>
    where
        H: ZkVmHost,
        H::Input<'a>: ZkVmInputBuilder<'a>,
    {
        let start = Instant::now();

        // Prepare the input using the host's input builder.
        let zkvm_input = Self::prepare_input::<H::Input<'a>>(input)?;

        let (_, cycles) = host.execute(zkvm_input)?;
        let execution_time = start.elapsed().as_millis();

        let _ = Self::prove(input, host)?;
        let proving_time = start.elapsed().as_millis();

        Ok(ProofReport {
            name: Self::name(),
            cycles,
            execution_time,
            proving_time,
        })
    }
}
