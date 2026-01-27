use zkaleido::{ProofType, ZkVmInputResult, ZkVmProgram};

pub struct FibProgram;

impl ZkVmProgram for FibProgram {
    type Input = u32;
    type Output = u32;

    fn name() -> String {
        "fibonacci".to_owned()
    }

    fn proof_type() -> zkaleido::ProofType {
        ProofType::Groth16
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: zkaleido::ZkVmInputBuilder<'a>,
    {
        B::new().write_serde(input)?.build()
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

#[cfg(test)]
pub mod tests {
    use zkaleido::ZkVmProgram;
    use zkaleido_native_adapter::NativeHost;

    use crate::{process_fibonacci, program::FibProgram};

    pub fn get_native_host() -> NativeHost {
        NativeHost::new(process_fibonacci)
    }

    #[test]
    fn test_native() {
        let input = 5;
        let host = get_native_host();
        let receipt = FibProgram::prove(&input, &host).unwrap();
        let output =
            FibProgram::process_output::<NativeHost>(receipt.receipt().public_values()).unwrap();
        assert_eq!(output, 5);
    }
}
