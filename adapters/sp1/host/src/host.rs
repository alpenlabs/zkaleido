use std::{env::var, fmt};

use sp1_sdk::{
    HashableKey, Prover, ProverClient, ProvingKey,
    env::{EnvProver, EnvProvingKey},
    network::{FulfillmentStrategy, NetworkMode},
};
use zkaleido::{ZkVm, ZkVmHost};

use crate::{SP1HostConfig, prover::block_on_async};

/// Host for the SP1 zkVM. Bundles a proving key (which embeds the guest ELF
/// and verifying key), a long-lived prover client and a configuration.  Implements [`ZkVmHost`],
/// [`zkaleido::ZkVmExecutor`], [`zkaleido::ZkVmProver`], and [`zkaleido::ZkVmRemoteProver`] across
/// the sibling modules in this crate.
#[derive(Clone)]
pub struct SP1Host {
    /// Proving key set up from the guest ELF in [`SP1Host::init_with_config`].
    /// Carries both the ELF (re-exposed via `elf()`) and the verifying key
    /// used for the program id and on-chain/local verification.
    pub(crate) proving_key: EnvProvingKey,
    /// Prover client built once in [`SP1Host::init_with_config`] from
    /// `SP1_PROVER` (and [`SP1HostConfig::proof_strategy`] for the network
    /// mode). Reused across execute, prove, verify, and remote prove.
    pub(crate) client: EnvProver,
    /// Per-instance behavioral knobs read at prove time: deadline and
    /// fulfillment strategy in [`crate::remote_prover`], poll cadence in the
    /// sync network path in [`crate::prover`].
    pub(crate) config: SP1HostConfig,
}

impl SP1Host {
    /// Initializes a new [`SP1Host`] with [`SP1HostConfig::default`],
    pub fn init(elf: &[u8]) -> Self {
        Self::init_with_config(elf, SP1HostConfig::default())
    }

    /// Initializes a new [`SP1Host`] with an explicit [`SP1HostConfig`].
    pub fn init_with_config(elf: &[u8], config: SP1HostConfig) -> Self {
        let client = block_on_async(build_env_prover(&config));
        let proving_key =
            block_on_async(client.setup(elf.into())).expect("failed to setup sp1 proving key");
        Self {
            proving_key,
            client,
            config,
        }
    }
}

/// Builds the [`EnvProver`] for `SP1_PROVER`. Mostly defers to
/// [`EnvProver::new`], but for `SP1_PROVER=network` we construct the
/// [`sp1_sdk::NetworkProver`] ourselves so that the configured fulfillment
/// strategy can route to the reserved cluster — `EnvProver::new` always picks
/// the default network mode.
async fn build_env_prover(config: &SP1HostConfig) -> EnvProver {
    let is_network = matches!(var("SP1_PROVER").as_deref(), Ok("network"));
    if is_network && config.proof_strategy == FulfillmentStrategy::Reserved {
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
