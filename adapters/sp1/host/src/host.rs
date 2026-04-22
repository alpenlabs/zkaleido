use std::{fmt, time::Duration};

use sp1_sdk::{HashableKey, ProverClient, SP1ProvingKey};
use zkaleido::{ZkVm, ZkVmHost};

/// A host for the `SP1` zkVM that stores the guest program in ELF format.
/// The `SP1Host` is responsible for program execution and proving
#[derive(Clone)]
pub struct SP1Host {
    /// Proving Key
    pub proving_key: SP1ProvingKey,
    /// Optional deadline passed to the SP1 prover network. When unset, the SP1
    /// SDK falls back to its own default (auto-calculated from the gas limit).
    pub(crate) deadline: Option<Duration>,
}

impl SP1Host {
    /// Creates a new instance of [`SP1Host`] using the provided [`SP1ProvingKey`].
    pub fn new(proving_key: SP1ProvingKey) -> Self {
        Self {
            proving_key,
            deadline: None,
        }
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
        SP1Host::new(proving_key)
    }

    /// Sets the deadline for remote proof requests submitted through this host.
    ///
    /// The deadline is passed to the SP1 prover network on every request; the
    /// network rejects the proof once the deadline elapses. Affects both the
    /// synchronous network path in [`ZkVmProver::prove_inner`] (when
    /// `SP1_PROVER=network`) and the async [`ZkVmRemoteProver::start_proving`] path.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }
}

impl ZkVmHost for SP1Host {
    fn zkvm(&self) -> ZkVm {
        ZkVm::SP1
    }
}

impl fmt::Debug for SP1Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sp1_{}", self.proving_key.vk.bytes32())
    }
}
