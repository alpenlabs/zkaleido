use std::fmt;

use hex::encode;
use risc0_zkvm::{compute_image_id, sha::Digest};
use zkaleido::ZkVmHost;

/// A host for the `Risc0` zkVM that stores the guest program in ELF format
/// The `Risc0Host` is responsible for program execution and proving
#[derive(Clone)]
pub struct Risc0Host {
    /// Elf
    pub elf: Vec<u8>,
    /// Id
    pub id: Digest,
}

impl Risc0Host {
    /// Initializes the Risc0Host with the given ELF.
    pub fn init(elf: &[u8]) -> Self {
        let id = compute_image_id(elf).expect("invalid elf");
        Risc0Host {
            elf: elf.to_vec(),
            id,
        }
    }
}

impl fmt::Debug for Risc0Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "risc0_{}", encode(self.id.as_bytes()))
    }
}

impl ZkVmHost for Risc0Host {}
