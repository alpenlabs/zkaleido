use bincode::deserialize;
use serde::{de::DeserializeOwned, Serialize};
#[cfg(feature = "zkvm-verify")]
use sha2::{Digest, Sha256};
use sp1_zkvm::io;
#[cfg(feature = "zkvm-verify")]
use sp1_zkvm::lib::verify::verify_sp1_proof;
use zkaleido::ZkVmEnv;

/// An environment adapter for the SP1 proof system implementing [`ZkVmEnv`].
///
/// This struct provides methods to read and commit data (both raw buffers and
/// Serde-serialized items) in the SP1 guest environment. It also supports
/// verification of both native SP1 proofs and Groth16 proofs within the
/// SP1 runtime.
#[derive(Debug)]
pub struct Sp1ZkVmEnv;

impl ZkVmEnv for Sp1ZkVmEnv {
    fn read_serde<T: DeserializeOwned>(&self) -> T {
        io::read()
    }

    fn read_buf(&self) -> Vec<u8> {
        io::read_vec()
    }

    fn commit_serde<T: Serialize>(&self, output: &T) {
        io::commit(&output);
    }

    fn commit_buf(&self, output_raw: &[u8]) {
        io::commit_slice(output_raw);
    }

    fn verify_native_proof(&self, vk_digest: &[u32; 8], public_values: &[u8]) {
        cfg_if::cfg_if! {
            if #[cfg(feature = "zkvm-verify")] {
                let pv_digest = Sha256::digest(public_values);
                verify_sp1_proof(vk_digest, &pv_digest.into());
            } else if #[cfg(feature = "mock-verify")] {}
            else {
                panic!(
                    "No verification feature enabled. \
                     Please enable either `zkvm-verify` or `mock-verify`."
                );
            }
        }
    }

    fn read_verified_serde<T: DeserializeOwned>(&self, vk_digest: &[u32; 8]) -> T {
        let buf = self.read_verified_buf(vk_digest);
        deserialize(&buf).expect("bincode deserialization failed")
    }
}
