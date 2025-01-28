use std::time::Instant;

use crate::{
    host::ZkVmHost, input::ZkVmInputBuilder, ProofReceipt, ProofReport, ProofType, PublicValues,
    ZkVmInputResult, ZkVmResult,
};

/// A trait representing a "prover" that can produce zero-knowledge proofs using a ZkVM.
///
/// This trait is host-agnostic, meaning it can generate proofs using any type that
/// implements [`ZkVmHost`]. The specific host is passed as a parameter to methods like
/// [`prove`] and [`perf_report`], allowing the prover to be flexible and work with
/// different backends or proof systems.
pub trait ZkVmProver {
    /// Represents the input data needed by the ZkVM to generate a proof.
    ///
    /// Typically, this includes any private data, parameters, or public information
    /// necessary for the proof. It will be transformed into a ZkVM-specific format using a
    /// [`ZkVmInputBuilder`]. Implementers of this trait should define how the input
    /// structure is created, validated, and passed along to the ZkVM for proof generation.
    type Input;

    /// Represents the final, verifiable output produced by the proven computation.
    ///
    /// Because the ZkVM returns proof results and other metadata as a stream of bytes
    /// (captured in [`PublicValues`]), this output type defines how those bytes are parsed
    /// and interpreted into a domain-specific result. Implementers should provide the logic
    /// necessary to convert the raw `PublicValues` into this structured, validated form.
    type Output;

    /// Returns a human-readable name for this prover.
    ///
    /// This name can be used for identification, logging, or debugging.
    fn name() -> String;

    /// Returns the type of proof this prover generates.
    ///
    /// Hosts can use this to decide how to handle or route proof generation tasks.
    fn proof_type() -> ProofType;

    /// Prepares the input for the ZkVM by converting [`Self::Input`] into a type usable
    /// by a [`ZkVmInputBuilder`].
    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: ZkVmInputBuilder<'a>;

    /// Processes the [`PublicValues`] from the ZkVM proof to produce the final [`Self::Output`].
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

    /// Generates a performance report for the proof process using a specified host.
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
