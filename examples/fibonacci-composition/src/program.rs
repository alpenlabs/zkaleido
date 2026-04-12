use zkaleido::{AggregationInput, ProgramId, ProofType, ZkVmInputResult, ZkVmProgram};

pub struct FibCompositionInput {
    pub fib_proof_with_vk: AggregationInput,
    pub fib_program_id: ProgramId,
}

pub struct FibCompositionProgram;

impl ZkVmProgram for FibCompositionProgram {
    type Input = FibCompositionInput;
    type Output = u32;

    fn name() -> String {
        "fibonacci composition".to_owned()
    }

    fn proof_type() -> zkaleido::ProofType {
        ProofType::Compressed
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: zkaleido::ZkVmInputBuilder<'a>,
    {
        B::new()
            .write_serde(&input.fib_program_id)?
            .write_proof(&input.fib_proof_with_vk)?
            .build()
    }

    fn process_output<H>(
        public_values: &zkaleido::PublicValues,
    ) -> zkaleido::ZkVmResult<Self::Output>
    where
        H: zkaleido::ZkVmHost,
    {
        H::extract_serde_public_output(public_values)
    }
}
