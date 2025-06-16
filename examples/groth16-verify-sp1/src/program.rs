use zkaleido::{ProofType, ZkVmInputResult, ZkVmProgram, ZkVmProgramPerf};

use crate::input::SP1Groth16VerifyInput;

pub struct SP1Groth16VerifyProgram;

impl ZkVmProgram for SP1Groth16VerifyProgram {
    type Input = SP1Groth16VerifyInput;
    type Output = bool;

    fn name() -> String {
        "groth16_verify".to_string()
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

impl ZkVmProgramPerf for SP1Groth16VerifyProgram {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zkaleido::ZkVmProgram;
    use zkaleido_native_adapter::{NativeHost, NativeMachine};

    use crate::{
        input::SP1Groth16VerifyInput, process_groth16_verify_sp1, program::SP1Groth16VerifyProgram,
    };

    fn get_native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                process_groth16_verify_sp1(zkvm);
                Ok(())
            })),
        }
    }

    #[test]
    fn test_native() {
        let input = SP1Groth16VerifyInput::load();
        let host = get_native_host();
        let receipt = SP1Groth16VerifyProgram::prove(&input, &host).unwrap();
        let is_verified =
            SP1Groth16VerifyProgram::process_output::<NativeHost>(receipt.public_values()).unwrap();

        assert!(is_verified);
    }
}
