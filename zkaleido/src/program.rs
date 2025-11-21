use async_trait::async_trait;

use crate::{
    host::ZkVmHost, input::ZkVmInputBuilder, PerformanceReport, ProofReceiptWithMetadata,
    ProofType, PublicValues, ZkVmHostPerf, ZkVmInputResult, ZkVmRemoteHost, ZkVmResult,
};

/// A trait representing a "program" whose zero-knowledge proofs can be produced using a ZkVM.
///
/// This trait is host-agnostic, meaning it can generate proofs using any type that
/// implements [`ZkVmHost`]. The specific host is passed as a parameter to methods like
/// `prove` and `perf_report`, allowing the program to be flexible and work with
/// different backends or proof systems.
pub trait ZkVmProgram {
    /// Represents the input data needed by the program.
    ///
    /// Typically, this includes any private data, parameters, or public information
    /// necessary for the proof. It will be transformed into a ZkVM-specific format using a
    /// [`ZkVmInputBuilder`]. Implementers of this trait should define how the input
    /// structure is created, validated, and passed along to the ZkVM for proof generation.
    type Input;

    /// Represents the final, verifiable output produced by the program.
    ///
    /// Because the ZkVM returns proof results and other metadata as a stream of bytes
    /// (captured in [`PublicValues`]), this output type defines how those bytes are parsed
    /// and interpreted into a domain-specific result. Implementers should provide the logic
    /// necessary to convert the raw `PublicValues` into this structured, validated form.
    type Output;

    /// Returns a human-readable name for this program.
    ///
    /// This name can be used for identification, logging, or debugging.
    fn name() -> String;

    /// Returns the type of proof this program generates.
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

    /// Prepares the program’s input for the ZkVM, and—if the `ZKVM_PROFILING_DUMP` environment
    /// variable is set to `1` or `true` (case‐insensitive)—automatically saves a host trace.
    fn prepare_input_with_profiling<'a, H>(
        input: &'a Self::Input,
        host: &H,
    ) -> ZkVmInputResult<<H::Input<'a> as ZkVmInputBuilder<'a>>::Input>
    where
        H: ZkVmHost,
        H::Input<'a>: ZkVmInputBuilder<'a>,
    {
        // 1) Check for profiling flag
        if std::env::var("ZKVM_PROFILING_DUMP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            // 2) Dump a trace via the host before building inputs
            host.save_trace(&Self::name());
        }

        // 3) Delegate to the implementor’s original prepare_input
        Self::prepare_input::<H::Input<'a>>(input)
    }

    /// Executes the computation using any zkVM host to get the output.
    fn execute<'a, H>(input: &'a Self::Input, host: &H) -> ZkVmResult<Self::Output>
    where
        H: ZkVmHost,
        H::Input<'a>: ZkVmInputBuilder<'a>,
    {
        // Prepare the input using the host's input builder.
        let zkvm_input = Self::prepare_input_with_profiling(input, host)?;

        // Use the host to execute.
        let public_values = host.execute(zkvm_input)?;

        // Process output to see if we are getting the expected type.
        Self::process_output::<H>(&public_values)
    }

    /// Proves the computation using any zkVM host.
    fn prove<'a, H>(input: &'a Self::Input, host: &H) -> ZkVmResult<ProofReceiptWithMetadata>
    where
        H: ZkVmHost,
        H::Input<'a>: ZkVmInputBuilder<'a>,
    {
        // Prepare the input using the host's input builder.
        let zkvm_input = Self::prepare_input_with_profiling(input, host)?;

        // Use the host to prove.
        let receipt_with_metadata = host.prove(zkvm_input, Self::proof_type())?;

        // Process output to see if we are getting the expected type.
        let _ = Self::process_output::<H>(receipt_with_metadata.receipt().public_values())?;

        // Dump the proof to file if flag is enabled
        if std::env::var("ZKVM_PROOF_DUMP")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            let receipt_name = format!("{}_{:?}.proof", Self::name(), host);
            receipt_with_metadata.save(receipt_name).unwrap();
        }

        Ok(receipt_with_metadata)
    }
}

/// Extends the [`ZkVmProgram`] trait by providing functionality to generate performance reports.
///
/// This trait introduces an additional method, `perf_report`, which accepts an input and returns a
/// [`PerformanceReport`].
pub trait ZkVmProgramPerf: ZkVmProgram {
    /// Generates a performance report for the proof process using a specified host.
    fn perf_report<'a, H>(input: &'a Self::Input, host: &H) -> ZkVmResult<PerformanceReport>
    where
        H: ZkVmHostPerf,
        H::Input<'a>: ZkVmInputBuilder<'a>,
    {
        // Prepare the input using the host's input builder.
        let input = Self::prepare_input_with_profiling(input, host)?;

        // Generate the perf report and set proper name in the report
        let mut perf_report = host.perf_report(input);
        perf_report.name = Self::name();

        Ok(perf_report)
    }
}

/// Blanket implementation of `ZkVmProgramPerf` for any type that implements `ZkVmProgram`.
///
/// This allows any program that provides the necessary `ZkVmProgram` implementation to
/// automatically satisfy the `ZkVmProgramPerf` trait without requiring explicit implementations.
/// The default `perf_report` method provided by the trait is sufficient for most use cases.
impl<T: ZkVmProgram> ZkVmProgramPerf for T {}

/// A trait representing a zkVM program that supports remote proving operations.
///
/// This trait extends [`ZkVmProgram`] to allow proof generation to be performed using remote
/// proving capabilities. While the core logic of the program remains host-agnostic, implementations
/// that use this trait can leverage a remote prover (one implementing `ZkVmRemoteProver`)
/// to initiate asynchronous proof generation via the `start_proving` method, and later retrieve the
/// proof once it is ready.
#[async_trait(?Send)]
pub trait ZkVmRemoteProgram: ZkVmProgram {
    /// Proves the computation using any zkVM host.
    async fn start_proving<'a, H>(input: &'a Self::Input, host: &H) -> ZkVmResult<String>
    where
        H: ZkVmRemoteHost,
        H::Input<'a>: ZkVmInputBuilder<'a>,
    {
        // Prepare the input using the host's input builder.
        let zkvm_input = Self::prepare_input::<H::Input<'a>>(input)?;

        host.start_proving(zkvm_input, Self::proof_type()).await
    }
}

/// Blanket implementation of `ZkVmRemoteProgram` for any type that implements `ZkVmProgram`.
///
/// This allows any program that provides the necessary `ZkVmProgram` implementation to
/// automatically satisfy the `ZkVmRemoteProgram` trait without requiring explicit implementations.
/// The default `start_proving` method provided by the trait is sufficient for most use cases.
#[async_trait(?Send)]
impl<T: ZkVmProgram> ZkVmRemoteProgram for T {}
