use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zkaleido::{ProofReceipt, ProofType, ZkVmEnv, ZkVmInputResult, ZkVmProgram, ZkVmProgramPerf};
use zkaleido_sp1_groth16_verifier::SP1Groth16Verifier;

pub fn process_groth16_verify(zkvm: &impl ZkVmEnv) {
    let Groth16VerifyInput {
        risc0_receipt,
        risc0_vk,
        sp1_receipt,
        sp1_vk,
    } = zkvm.read_serde();

    let risc0_verified =
        zkaleido_risc0_groth16_verifier::verify_groth16(&risc0_receipt, &risc0_vk).is_ok();

    let sp1_verifier =
        SP1Groth16Verifier::load(include_bytes!("../vk/sp1_groth16_vk.bin"), sp1_vk).unwrap();
    let sp1_verified = sp1_verifier
        .verify(
            sp1_receipt.proof().as_bytes(),
            sp1_receipt.public_values().as_bytes(),
        )
        .is_ok();

    zkvm.commit_serde(&(risc0_verified, sp1_verified));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16VerifyInput {
    risc0_receipt: ProofReceipt,
    risc0_vk: [u8; 32],
    sp1_receipt: ProofReceipt,
    sp1_vk: [u8; 32],
}

impl Groth16VerifyInput {
    pub fn load() -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        let sp1_vk_hex = "0000e3572a33647cba427acbaecac23a01e237a8140d2c91b3873457beb5be13";
        let sp1_vk: [u8; 32] = hex::decode(sp1_vk_hex).unwrap().try_into().unwrap();
        let sp1_proof_file = base.join(format!(
            "../../adapters/sp1/groth16-verifier/proofs/fibonacci_sp1_0x{}.proof.bin",
            sp1_vk_hex
        ));
        let sp1_receipt = ProofReceipt::load(sp1_proof_file).unwrap();

        let risc0_vk_hex = "25eaa741d5cb0d99fe15ce60c4bf3886f96932f22ee67041f0b4165203ef5a02";
        let risc0_vk: [u8; 32] = hex::decode(risc0_vk_hex).unwrap().try_into().unwrap();
        let proof_file = base.join(format!(
            "../../adapters/risc0/groth16-verifier/proofs/fibonacci_risc0_{}.proof.bin",
            risc0_vk_hex
        ));
        let risc0_receipt = ProofReceipt::load(proof_file).unwrap();

        Groth16VerifyInput {
            risc0_receipt,
            risc0_vk,
            sp1_receipt,
            sp1_vk,
        }
    }
}

pub struct Groth16VerifyProgram;

impl ZkVmProgram for Groth16VerifyProgram {
    type Input = Groth16VerifyInput;
    type Output = (bool, bool);

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

impl ZkVmProgramPerf for Groth16VerifyProgram {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zkaleido::ZkVmProgram;
    use zkaleido_native_adapter::{NativeHost, NativeMachine};

    use super::process_groth16_verify;
    use crate::{Groth16VerifyInput, Groth16VerifyProgram};

    fn get_native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                process_groth16_verify(zkvm);
                Ok(())
            })),
        }
    }

    #[test]
    fn test_native() {
        let input = Groth16VerifyInput::load();
        let host = get_native_host();
        let receipt = Groth16VerifyProgram::prove(&input, &host).unwrap();
        let public_params =
            Groth16VerifyProgram::process_output::<NativeHost>(receipt.public_values()).unwrap();

        assert_eq!(public_params, (true, true));
    }
}
