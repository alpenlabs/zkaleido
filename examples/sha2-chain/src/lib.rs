use sha2::{Digest, Sha256};
use zkaleido::{ProofType, ZkVmEnv, ZkVmInputResult, ZkVmProgram, ZkVmProgramPerf};

const MESSAGE_TO_HASH: &str = "Hello, world!";

pub fn process_sha2_chain(zkvm: &impl ZkVmEnv) {
    let rounds: u32 = zkvm.read_serde();
    let final_hash = hash_n_rounds(MESSAGE_TO_HASH, rounds);

    zkvm.commit_serde(&final_hash);
}

fn hash_n_rounds(message: &str, rounds: u32) -> [u8; 32] {
    let mut current_hash = {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        hasher.finalize()
    };

    // Perform additional rounds of hashing
    for _ in 1..rounds {
        let mut hasher = Sha256::new();
        hasher.update(current_hash);
        current_hash = hasher.finalize();
    }

    current_hash.into()
}

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

impl ZkVmProgramPerf for ShaChainProgram {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zkaleido::ZkVmProgram;
    use zkaleido_native_adapter::{NativeHost, NativeMachine};

    use super::process_sha2_chain;
    use crate::ShaChainProgram;

    fn get_native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                process_sha2_chain(zkvm);
                Ok(())
            })),
        }
    }

    #[test]
    fn test_native() {
        let input = 5;
        let host = get_native_host();
        let receipt = ShaChainProgram::prove(&input, &host).unwrap();
        let public_params =
            ShaChainProgram::process_output::<NativeHost>(receipt.public_values()).unwrap();

        assert!(public_params != [0; 32]);
    }
}
