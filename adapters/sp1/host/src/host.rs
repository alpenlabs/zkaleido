use std::{env::var, fmt, time::Duration};

use sp1_sdk::{
    HashableKey, Prover, ProverClient, ProvingKey,
    env::{EnvProver, EnvProvingKey},
    network::{FulfillmentStrategy, NetworkMode},
};
use zkaleido::{ZkVm, ZkVmHost};

use crate::prover::{block_on_async, proof_strategy};

/// A host for the `SP1` zkVM that stores the guest program in ELF format.
/// The `SP1Host` is responsible for program execution and proving
#[derive(Clone)]
pub struct SP1Host {
    /// Proving Key
    pub(crate) proving_key: EnvProvingKey,
    /// Optional deadline passed to the SP1 prover network. When unset, the SP1
    /// SDK falls back to its own default (auto-calculated from the gas limit).
    pub(crate) deadline: Option<Duration>,
    /// The SP1 prover client, picked once at [`SP1Host::init`] from `SP1_PROVER`
    /// and reused for execute, prove, and verify across [`crate::prover`],
    /// [`crate::verifier`], and [`crate::remote_prover`].
    pub(crate) client: EnvProver,
}

impl SP1Host {
    /// Initializes a new [`SP1Host`] by selecting the prover backend from the
    /// environment and setting up the proving key for `elf`.
    ///
    /// `SP1_PROVER` selects the backend (`cpu` is the default; `mock`, `cuda`,
    /// `light`, and `network` are also accepted). When `SP1_PROVER=network`,
    /// `SP1_PROOF_STRATEGY=RESERVED` switches the network client to the
    /// reserved cluster.
    pub fn init(elf: &[u8]) -> Self {
        let client = block_on_async(build_env_prover());
        let proving_key =
            block_on_async(client.setup(elf.into())).expect("failed to setup sp1 proving key");
        Self {
            proving_key,
            deadline: None,
            client,
        }
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

/// Builds the [`EnvProver`] for `SP1_PROVER`. Mostly defers to
/// [`EnvProver::new`], but for `SP1_PROVER=network` we construct the
/// [`NetworkProver`] ourselves so that `SP1_PROOF_STRATEGY=RESERVED` can route
/// to the reserved cluster — `EnvProver::new` always picks the default
/// network mode.
async fn build_env_prover() -> EnvProver {
    let is_network = matches!(var("SP1_PROVER").as_deref(), Ok("network"));
    if is_network && proof_strategy() == FulfillmentStrategy::Reserved {
        let np = ProverClient::builder()
            .network_for(NetworkMode::Reserved)
            .build()
            .await;
        EnvProver::Network(np)
    } else {
        EnvProver::new().await
    }
}

impl ZkVmHost for SP1Host {
    fn zkvm(&self) -> ZkVm {
        ZkVm::SP1
    }
}

impl fmt::Debug for SP1Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}_{}",
            self.zkvm(),
            self.proving_key.verifying_key().bytes32()
        )
    }
}
