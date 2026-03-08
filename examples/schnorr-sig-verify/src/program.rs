use zkaleido::{ProofType, ZkVmInputResult, ZkVmProgram};

use crate::input::SchnorrSigInput;

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
            .write_ssz(&input.sig)?
            .write_ssz(&input.msg)?
            .write_ssz(&input.pk)?
            .build()
    }

    fn process_output<H>(
        public_values: &zkaleido::PublicValues,
    ) -> zkaleido::ZkVmResult<Self::Output>
    where
        H: zkaleido::ZkVmHost,
    {
        H::extract_ssz_public_output(public_values)
    }
}

#[cfg(test)]
mod tests {
    use zkaleido::ZkVmProgram;
    use zkaleido_native_adapter::NativeHost;

    use super::*;
    use crate::process_schnorr_sig_verify;

    fn get_native_host() -> NativeHost {
        NativeHost::new(process_schnorr_sig_verify)
    }

    #[test]
    fn test_native() {
        let input = SchnorrSigInput::new_random();
        let host = get_native_host();
        let receipt = SchnorrSigProgram::prove(&input, &host).unwrap();
        let output =
            SchnorrSigProgram::process_output::<NativeHost>(receipt.receipt().public_values())
                .unwrap();
        assert!(output);
    }
}
