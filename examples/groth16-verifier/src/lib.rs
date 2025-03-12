use serde::{Deserialize, Serialize};
use zkaleido::{ProofReceipt, ProofType, ZkVmEnv, ZkVmInputResult, ZkVmProgram, ZkVmProgramPerf};

pub fn process_groth16_proofs(zkvm: &impl ZkVmEnv) {
    let Groth16VerifierInput {
        risc0_receipt,
        risc0_vk,
        sp1_receipt,
        sp1_vk,
    } = zkvm.read_serde();

    let risc0_verified =
        zkaleido_risc0_groth16_verifier::verify_groth16(&risc0_receipt, &risc0_vk).is_ok();

    let sp1_verified = zkaleido_sp1_groth16_verifier::verify_groth16(&sp1_receipt, &sp1_vk).is_ok();

    zkvm.commit_serde(&(risc0_verified, sp1_verified));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16VerifierInput {
    risc0_receipt: ProofReceipt,
    risc0_vk: [u8; 32],
    sp1_receipt: ProofReceipt,
    sp1_vk: [u8; 32],
}

impl Groth16VerifierInput {
    pub fn load() -> Self {
        let sp1_vk_hex = "00bf077c28baa685b0a9ec0b8d47eb51bc98f5c048f5aa386ea156fe24995a35";
        let sp1_vk: [u8; 32] = hex::decode(sp1_vk_hex).unwrap().try_into().unwrap();
        let sp1_proof_file = format!(
            "../../adapters/sp1/groth16-verifier/proofs/fibonacci_sp1_0x{}.proof.bin",
            sp1_vk_hex
        );
        let sp1_receipt = ProofReceipt::load(sp1_proof_file).unwrap();

        let risc0_vk_hex = "0963493f27db6efac281ea2900ff4c611a93703cb9109dbd2231484121d08384";
        let risc0_vk: [u8; 32] = hex::decode(risc0_vk_hex).unwrap().try_into().unwrap();
        let proof_file = format!(
            "../../adapters/risc0/groth16-verifier/proofs/fibonacci_risc0_{}.proof.bin",
            risc0_vk_hex
        );
        let risc0_receipt = ProofReceipt::load(proof_file).unwrap();

        Groth16VerifierInput {
            risc0_receipt,
            risc0_vk,
            sp1_receipt,
            sp1_vk,
        }
    }
}

pub struct Groth16VerifierProgram;

impl ZkVmProgram for Groth16VerifierProgram {
    type Input = Groth16VerifierInput;
    type Output = (bool, bool);

    fn name() -> String {
        "groth16_verifier".to_string()
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

impl ZkVmProgramPerf for Groth16VerifierProgram {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zkaleido::ZkVmProgram;
    use zkaleido_native_adapter::{NativeHost, NativeMachine};

    use super::process_groth16_proofs;
    use crate::{Groth16VerifierInput, Groth16VerifierProgram};

    fn get_native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                process_groth16_proofs(zkvm);
                Ok(())
            })),
        }
    }

    #[test]
    fn test_native() {
        let input = Groth16VerifierInput::load();
        let host = get_native_host();
        let receipt = Groth16VerifierProgram::prove(&input, &host).unwrap();
        let public_params =
            Groth16VerifierProgram::process_output::<NativeHost>(receipt.public_values()).unwrap();

        assert_eq!(public_params, (true, true));
    }
}
