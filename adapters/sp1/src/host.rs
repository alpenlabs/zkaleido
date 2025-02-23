use std::fmt;

use sp1_sdk::{HashableKey, ProverClient, SP1ProvingKey};
use zkaleido::ZkVmHost;

/// A host for the `SP1` zkVM that stores the guest program in ELF format.
/// The `SP1Host` is responsible for program execution and proving
#[derive(Clone)]
pub struct SP1Host {
    /// Proving Key
    pub proving_key: SP1ProvingKey,
}

impl SP1Host {
    /// Creates a new instance of [`SP1Host`] using the provided [`SP1ProvingKey`].
    pub fn new(proving_key: SP1ProvingKey) -> Self {
        Self { proving_key }
    }

    /// Creates a new instance of [`SP1Host`] from serialized proving key bytes.
    pub fn new_from_pk_bytes(proving_key_bytes: &[u8]) -> Self {
        let proving_key: SP1ProvingKey =
            bincode::deserialize(proving_key_bytes).expect("invalid sp1 pk bytes");
        SP1Host::new(proving_key)
    }

    /// Initializes a new [`SP1Host`] by setting up the proving key using the provided ELF bytes.
    pub fn init(elf: &[u8]) -> Self {
        let client = ProverClient::from_env();
        let (proving_key, _) = client.setup(elf);
        Self { proving_key }
    }
}

impl ZkVmHost for SP1Host {}

impl fmt::Debug for SP1Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sp1_{}", self.proving_key.vk.bytes32())
    }
}
