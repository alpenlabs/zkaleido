use zkaleido::{AggregationInput, ProofType, ZkVmEnv, ZkVmInputResult, ZkVmProver};

pub fn process_fib_verification(zkvm: &impl ZkVmEnv) {
    // Read the verification key of sha2-chain program
    let fib_vk: [u32; 8] = zkvm.read_serde();
    let valid_fib_no: u32 = zkvm.read_verified_serde(&fib_vk);

    // Write the output of the program.
    zkvm.commit_serde(&valid_fib_no);
}

pub struct FibCompositionProver;

impl ZkVmProver for FibCompositionProver {
    type Input = AggregationInput;
    type Output = i32;

    fn name() -> String {
        "fibonacci verification".to_owned()
    }

    fn proof_type() -> zkaleido::ProofType {
        ProofType::Compressed
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: zkaleido::ZkVmInputBuilder<'a>,
    {
        B::new().write_proof(input)?.build()
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
