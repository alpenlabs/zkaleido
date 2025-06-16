use zkaleido::{ProofType, ZkVmInputResult, ZkVmProgram, ZkVmProgramPerf};

use crate::input::Risc0Groth16VerifyInput;

pub struct Risc0Groth16VerifyProgram;

impl ZkVmProgram for Risc0Groth16VerifyProgram {
    type Input = Risc0Groth16VerifyInput;
    type Output = bool;

    fn name() -> String {
        "risc0_groth16_verify".to_string()
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

impl ZkVmProgramPerf for Risc0Groth16VerifyProgram {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zkaleido::ZkVmProgram;
    use zkaleido_native_adapter::{NativeHost, NativeMachine};

    use crate::{
        input::Risc0Groth16VerifyInput, process_groth16_verify_risc0,
        program::Risc0Groth16VerifyProgram,
    };

    fn get_native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                process_groth16_verify_risc0(zkvm);
                Ok(())
            })),
        }
    }

    #[test]
    fn test_native() {
        let input = Risc0Groth16VerifyInput::load();
        let host = get_native_host();
        let receipt = Risc0Groth16VerifyProgram::prove(&input, &host).unwrap();
        let risc0_verified =
            Risc0Groth16VerifyProgram::process_output::<NativeHost>(receipt.public_values())
                .unwrap();

        assert!(risc0_verified);
    }
}
