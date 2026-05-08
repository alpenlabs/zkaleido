use std::{fmt, time::Duration};

use sp1_sdk::{
    HashableKey, ProvingKey, SP1ProvingKey,
    blocking::{Prover, ProverClient},
};
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
    /// Creates a new instance of [`SP1Host`] using the provided [`SP1ProvingKey`] and
    /// an optional deadline for remote proof requests.
    ///
    /// Pass `None` for `deadline` to let the SP1 SDK fall back to its own default
    /// (auto-calculated from the gas limit).
    pub fn new(proving_key: SP1ProvingKey, deadline: Option<Duration>) -> Self {
        Self {
            proving_key,
            deadline,
        }
    }

    /// Initializes a new [`SP1Host`] by setting up the proving key using the provided ELF bytes.
    pub fn init(elf: &[u8]) -> Self {
        let client = ProverClient::from_env();
        let env_proving_key = client
            .setup(elf.into())
            .expect("failed to setup sp1 proving key");
        let proving_key = SP1ProvingKey::new(
            env_proving_key.verifying_key().clone(),
            env_proving_key.elf().clone(),
        );
        SP1Host::new(proving_key, None)
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
        write!(f, "sp1_{}", self.proving_key.verifying_key().bytes32())
    }
}
