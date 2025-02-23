use std::fmt;

use hex::encode;
use risc0_zkvm::{compute_image_id, sha::Digest};
use zkaleido::ZkVmHost;

/// A host for the `Risc0` zkVM that stores the guest program in ELF format.
///
/// The `Risc0Host` is responsible for managing program execution and generating proofs of
/// computation. It encapsulates the guest program in its ELF representation along with a
/// verification key (`vk`) that uniquely identifies the program.
#[derive(Clone)]
pub struct Risc0Host {
    /// A vector of bytes containing the guest program in ELF format.
    elf: Vec<u8>,
    /// The verification key computed from the ELF, used to verify the integrity of the program.
    vk: Digest,
}

impl Risc0Host {
    /// Initializes the Risc0Host with the given ELF.
    pub fn init(elf: &[u8]) -> Self {
        let vk = compute_image_id(elf).expect("invalid elf");
        Risc0Host {
            elf: elf.to_vec(),
            vk,
        }
    }

    /// Returns a reference to the guest program in ELF format.
    pub fn elf(&self) -> &[u8] {
        &self.elf
    }

    /// Returns the verification key (`vk`) associated with the guest program.
    pub fn vk(&self) -> Digest {
        self.vk
    }
}

impl ZkVmHost for Risc0Host {}

impl fmt::Debug for Risc0Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "risc0_{}", encode(self.vk.as_bytes()))
    }
}
