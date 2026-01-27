use zkaleido::{ProofType, ZkVmInputResult, ZkVmProgram};

pub struct ShaChainProgram;

impl ZkVmProgram for ShaChainProgram {
    type Input = u32;
    type Output = [u8; 32];

    fn name() -> String {
        "sha2_chain".to_string()
    }

    fn proof_type() -> zkaleido::ProofType {
        ProofType::Core
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
mod tests {
    use zkaleido::{ZkVmProgram, ZkVmTypedVerifier};
    use zkaleido_native_adapter::NativeHost;

    use crate::{process_sha2_chain, program::ShaChainProgram};

    fn get_native_host() -> NativeHost {
        NativeHost::new(process_sha2_chain)
    }

    #[test]
    fn test_native() {
        let input = 5;
        let host = get_native_host();
        let receipt = ShaChainProgram::prove(&input, &host).unwrap();
        let public_params =
            ShaChainProgram::process_output::<NativeHost>(receipt.receipt().public_values())
                .unwrap();

        assert!(public_params != [0; 32]);
        assert!(host.verify(&receipt).is_ok());
    }
}
