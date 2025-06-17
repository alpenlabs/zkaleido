use sha2::{Digest, Sha256};
use zkaleido::ZkVmEnv;

const MESSAGE_TO_HASH: &str = "Hello, world!";
pub mod program;

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
