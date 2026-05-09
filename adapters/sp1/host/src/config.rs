use std::{env::var, time::Duration};

use sp1_sdk::network::FulfillmentStrategy;

const DEFAULT_NETWORK_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Per-instance behavioral configuration for an [`crate::SP1Host`].
///
/// Holds knobs that may legitimately differ between two `SP1Host` instances in
/// the same process (deadlines, fulfillment strategy, polling cadence).
/// Deployment-level toggles like the prover backend (`SP1_PROVER`) and mock
/// mode (`ZKVM_MOCK`) remain env-driven, since those are set once per binary.
#[derive(Clone, Debug)]
pub struct SP1HostConfig {
    /// Fulfillment strategy used for the network prover. Falls back to
    /// `SP1_PROOF_STRATEGY` in [`from_env`](Self::from_env), defaulting to
    /// [`FulfillmentStrategy::Auction`].
    pub proof_strategy: FulfillmentStrategy,
    /// Deadline forwarded to network proof requests. `None` defers to the SP1
    /// SDK's own default (auto-derived from the gas limit). Falls back to
    /// `SP1_DEADLINE_ENV_MS` (milliseconds) in [`from_env`](Self::from_env),
    /// defaulting to `None` when unset or unparsable.
    pub deadline: Option<Duration>,
    /// Poll cadence for `get_status` in the synchronous network proving path.
    /// Falls back to `SP1_NETWORK_POLL_ENV_MS` (milliseconds) in
    /// [`from_env`](Self::from_env), defaulting to 1 second.
    pub network_poll_interval: Duration,
}

impl SP1HostConfig {
    /// Builds a config with env-driven fallbacks: `SP1_PROOF_STRATEGY`
    /// (defaults to `Auction`), `SP1_NETWORK_POLL_ENV_MS` (milliseconds,
    /// defaults to 1 second), and `SP1_DEADLINE_ENV_MS` (milliseconds,
    /// defaults to `None`). Unparsable values fall back to the defaults.
    pub fn from_env() -> Self {
        let proof_strategy = var("SP1_PROOF_STRATEGY")
            .ok()
            .and_then(|s| FulfillmentStrategy::from_str_name(&s.to_ascii_uppercase()))
            .unwrap_or(FulfillmentStrategy::Auction);

        let deadline = var("SP1_DEADLINE_ENV_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_millis);

        let network_poll_interval = var("SP1_NETWORK_POLL_ENV_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_NETWORK_POLL_INTERVAL);

        Self {
            deadline,
            proof_strategy,
            network_poll_interval,
        }
    }

    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }

    #[must_use]
    pub fn with_proof_strategy(mut self, strategy: FulfillmentStrategy) -> Self {
        self.proof_strategy = strategy;
        self
    }

    #[must_use]
    pub fn with_network_poll_interval(mut self, interval: Duration) -> Self {
        self.network_poll_interval = interval;
        self
    }
}

impl Default for SP1HostConfig {
    fn default() -> Self {
        Self::from_env()
    }
}
