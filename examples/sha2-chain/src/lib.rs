use sha2::{Digest, Sha256};
use strata_zkvm::{ProofType, ZkVmEnv, ZkVmInputResult, ZkVmProver, ZkVmProverPerf};

const MESSAGE_TO_HASH: &str = "Hello, world!";

pub fn process_sha_chain(zkvm: &impl ZkVmEnv) {
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

pub struct ShaChainProver;

impl ZkVmProver for ShaChainProver {
    type Input = u32;
    type Output = [u8; 32];

    fn proof_type() -> strata_zkvm::ProofType {
        ProofType::Core
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: strata_zkvm::ZkVmInputBuilder<'a>,
    {
        B::new().write_serde(input)?.build()
    }

    fn process_output<H>(
        public_values: &strata_zkvm::PublicValues,
    ) -> strata_zkvm::ZkVmResult<Self::Output>
    where
        H: strata_zkvm::ZkVmHost,
    {
        H::extract_serde_public_output(public_values)
    }
}

impl ZkVmProverPerf for ShaChainProver {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use strata_native_zkvm_adapter::{NativeHost, NativeMachine};
    use strata_zkvm::ZkVmProver;

    use super::process_sha_chain;
    use crate::ShaChainProver;

    fn get_native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                process_sha_chain(zkvm);
                Ok(())
            })),
        }
    }

    #[test]
    fn test_native() {
        let input = 5;
        let host = get_native_host();
        let receipt = ShaChainProver::prove(&input, &host).unwrap();
        let public_params =
            ShaChainProver::process_output::<NativeHost>(receipt.public_values()).unwrap();

        assert!(public_params != [0; 32]);
    }
}
