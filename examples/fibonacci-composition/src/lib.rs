use zkaleido::{
    AggregationInput, ProofType, VerificationKeyCommitment, ZkVmEnv, ZkVmInputResult, ZkVmProver,
    ZkVmProverPerf,
};

pub fn process_fibonacci_composition(zkvm: &impl ZkVmEnv) {
    // Read the verification key of sha2-chain program
    let fib_vk: [u32; 8] = zkvm.read_serde();
    let valid_fib_no: u32 = zkvm.read_verified_serde(&fib_vk);
    zkvm.commit_serde(&valid_fib_no);
}

pub struct FibCompositionInput {
    pub fib_proof_with_vk: AggregationInput,
    pub fib_vk_commitment: VerificationKeyCommitment,
}

pub struct FibCompositionProver;

impl ZkVmProver for FibCompositionProver {
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
            .write_serde(&input.fib_vk_commitment.into_inner())?
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

impl ZkVmProverPerf for FibCompositionProver {}
