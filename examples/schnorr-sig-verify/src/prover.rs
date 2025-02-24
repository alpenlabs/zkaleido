use zkaleido::{ProofType, ZkVmEnv, ZkVmInputResult, ZkVmProgram, ZkVmProgramPerf};

use crate::{verify_schnorr_sig_k256, SchnorrSigInput};

pub fn process_schnorr_sig_verify(zkvm: &impl ZkVmEnv) {
    let sig = zkvm.read_buf();
    let msg: [u8; 32] = zkvm.read_serde();
    let pk: [u8; 32] = zkvm.read_serde();

    let result = verify_schnorr_sig_k256(&sig.try_into().unwrap(), &msg, &pk);

    zkvm.commit_serde(&result);
}

pub struct SchnorrSigProgram;

impl ZkVmProgram for SchnorrSigProgram {
    type Input = SchnorrSigInput;
    type Output = bool;

    fn name() -> String {
        "schnorr_sig_verify".to_string()
    }

    fn proof_type() -> ProofType {
        ProofType::Core
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: zkaleido::ZkVmInputBuilder<'a>,
    {
        B::new()
            .write_buf(&input.sig)?
            .write_serde(&input.msg)?
            .write_serde(&input.pk)?
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

impl ZkVmProgramPerf for SchnorrSigProgram {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zkaleido::ZkVmProgram;
    use zkaleido_native_adapter::{NativeHost, NativeMachine};

    use super::*;

    fn get_native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                process_schnorr_sig_verify(zkvm);
                Ok(())
            })),
        }
    }

    #[test]
    fn test_native() {
        let input = SchnorrSigInput::new_random();
        let host = get_native_host();
        let receipt = SchnorrSigProgram::prove(&input, &host).unwrap();
        let output =
            SchnorrSigProgram::process_output::<NativeHost>(receipt.public_values()).unwrap();
        assert!(output);
    }
}
