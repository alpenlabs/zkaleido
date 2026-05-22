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
    /// [`FulfillmentStrategy::Auction`] when unset. An unparsable value
    /// panics — silently routing to the wrong cluster would be worse.
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
    /// When `true`, [`crate::SP1Host`]'s execute path and the pre-flight
    /// inside its start_proving / prove_inner paths reject guests that
    /// halted with a non-zero `report.exit_code` (panicked), returning
    /// [`zkaleido::ZkVmError::ExecutionError`]. Mirrors `require_success`
    /// on `SP1Groth16Verifier` in the `zkaleido-sp1-groth16-verifier`
    /// crate.
    ///
    /// The SP1 executor and the SDK's network simulation both accept a
    /// non-zero exit code as a successful run, so without this gate the
    /// host would silently submit network requests the guest is going to
    /// panic on. Defaults to `true`; set to `false` to opt back into the
    /// permissive behavior (e.g. testing a guest's panic path end-to-end).
    /// Falls back to `SP1_REQUIRE_SUCCESS` (`true` / `false`,
    /// case-insensitive) in [`from_env`](Self::from_env); unparsable
    /// values default to `true`.
    pub require_success: bool,
}

impl SP1HostConfig {
    /// Builds a config with env-driven fallbacks: `SP1_PROOF_STRATEGY`
    /// (defaults to `Auction`), `SP1_NETWORK_POLL_ENV_MS` (milliseconds,
    /// defaults to 1 second), and `SP1_DEADLINE_ENV_MS` (milliseconds,
    /// defaults to `None`). Unparsable numeric values fall back to the
    /// defaults; an unparsable `SP1_PROOF_STRATEGY` panics.
    pub fn from_env() -> Self {
        let proof_strategy = match var("SP1_PROOF_STRATEGY") {
            Ok(s) => {
                FulfillmentStrategy::from_str_name(&s.to_ascii_uppercase()).unwrap_or_else(|| {
                    panic!(
                        "SP1_PROOF_STRATEGY={s:?} is not a valid FulfillmentStrategy \
                         (expected one of: auction, hosted, reserved)"
                    )
                })
            }
            Err(_) => FulfillmentStrategy::Auction,
        };

        let deadline = var("SP1_DEADLINE_ENV_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_millis);

        let network_poll_interval = var("SP1_NETWORK_POLL_ENV_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_NETWORK_POLL_INTERVAL);

        let require_success = var("SP1_REQUIRE_SUCCESS")
            .ok()
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(true);

        Self {
            deadline,
            proof_strategy,
            network_poll_interval,
            require_success,
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

    #[must_use]
    pub fn with_require_success(mut self, require_success: bool) -> Self {
        self.require_success = require_success;
        self
    }
}

impl Default for SP1HostConfig {
    fn default() -> Self {
        Self::from_env()
    }
}
