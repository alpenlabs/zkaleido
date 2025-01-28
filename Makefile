# Heavily inspired by Reth: https://github.com/paradigmxyz/reth/blob/d599393771f9d7d137ea4abf271e1bd118184c73/Makefile
.DEFAULT_GOAL := help

GIT_TAG ?= $(shell git describe --tags --abbrev=0)

BUILD_PATH = "target"

# Cargo profile for builds. Default is for local builds, CI uses an override.
PROFILE ?= release

# Extra flags for Cargo
CARGO_INSTALL_EXTRA_FLAGS ?=

# List of features to use for building
FEATURES ?=

# List of programs
PROGRAMS ?= fibonacci-composition,sha2-chain,schnorr-sig-verify

# ZkVm to use
ZKVM ?= sp1

##@ Help

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build

.PHONY: build
build: ## Build the workspace into the `target` directory.
	cargo build --workspace --bin "zkaleido-runner" --features "$(FEATURES)" --profile "$(PROFILE)"
##@ Test

UNIT_TEST_ARGS := --locked --workspace -E 'kind(lib)' -E 'kind(bin)' -E 'kind(proc-macro)'
COV_FILE := lcov.info

.PHONY: test-unit
test-unit: ## Run unit tests.
	-cargo install cargo-nextest --locked
	cargo nextest run $(UNIT_TEST_ARGS)

.PHONY: cov-unit
cov-unit: ## Run unit tests with coverage.
	rm -f $(COV_FILE)
	cargo llvm-cov nextest --lcov --output-path $(COV_FILE) $(UNIT_TEST_ARGS)

.PHONY: cov-report-html
cov-report-html: ## Generate an HTML coverage report and open it in the browser.
	cargo llvm-cov --open --workspace --locked nextest

.PHONY: mutants-test
mutants-test: ## Runs `nextest` under `cargo-mutants`. Caution: This can take *really* long to run.
	cargo mutants --workspace -j2

.PHONY: sec
sec: ## Check for security advisories on any dependencies.
	cargo audit #  HACK: not denying warnings as we depend on `yaml-rust` via `format-serde-error` which is unmaintained


##@ Prover

.PHONY: report
report: prover-clean ## Generate proof report for programs for all supported ZkVm
	cargo run --release -- --programs $(PROGRAMS)

.PHONY: report-sp1
report-sp1: prover-clean ## Generate SP1 proof report for given programs
	cargo run --release --no-default-features -F sp1-mock -- --programs $(PROGRAMS)

.PHONY: report-risc0
report-risc0: prover-clean ## Generate Risc0 proof report for given programs
	cargo run --release --no-default-features -F risc0-mock -- --programs $(PROGRAMS)

.PHONY: proof
proof: ## Generate proof for the given program using the given ZkVm
	ZKVM_PROOF_DUMP=1 cargo run --release --no-default-features -F $(ZKVM) -- --programs $(PROGRAMS)

.PHONY: prover-clean
prover-clean: ## Cleans up proofs and profiling data generated
	rm -rf *.trace_profile
	rm -rf *.proof

##@ Code Quality

.PHONY: fmt-check-ws
fmt-check-ws: ## Check formatting issues but do not fix automatically.
	cargo fmt --check

.PHONY: fmt-ws
fmt-ws: ## Format source code in the workspace.
	cargo fmt --all

.PHONY: ensure-taplo
ensure-taplo:
	@if ! command -v taplo &> /dev/null; then \
		echo "taplo not found. Please install it by following the instructions from: https://taplo.tamasfe.dev/cli/installation/binary.html" \
		exit 1; \
    fi

.PHONY: fmt-check-toml
fmt-check-toml: ensure-taplo ## Runs `taplo` to check that TOML files are properly formatted
	taplo fmt --check

.PHONY: fmt-toml
fmt-toml: ensure-taplo ## Runs `taplo` to format TOML files
	taplo fmt

define lint-pkg
	find $(1) -type f -name "Cargo.toml" -exec sh -c \
	'f="$$1"; echo "Clippy for $${f}" && \
	cargo clippy --manifest-path $${f} --all-features -- -D warnings' shell {} \; 
endef

.PHONY: lint-check-ws
lint-check-ws: ## Checks for lint issues in the workspace.
	$(call lint-pkg,examples) && $(call lint-pkg,adapters)

define lint-pkg-fix
	find $(1) -type f -name "Cargo.toml" -exec sh -c \
	'f="$$1"; echo "Clippy for $${f}" && \
	cargo clippy --manifest-path $${f} --all-features --fix -- -D warnings' shell {} \; 
endef

.PHONY: lint-fix-ws
lint-fix-ws: ## Lints the workspace and applies fixes where possible.
	$(call lint-pkg-fix,examples) && $(call lint-pkg-fix,adapters)

ensure-codespell:
	@if ! command -v codespell &> /dev/null; then \
		echo "codespell not found. Please install it by running the command 'pip install codespell' or refer to the following link for more information: https://github.com/codespell-project/codespell" \
		exit 1; \
    fi

.PHONY: lint-codespell
lint-check-codespell: ensure-codespell ## Runs `codespell` to check for spelling errors.
	codespell

.PHONY: lint-fix-codespell
lint-fix-codespell: ensure-codespell ## Runs `codespell` to fix spelling errors if possible.
	codespell -w

.PHONY: lint-toml
lint-check-toml: ensure-taplo ## Lints TOML files
	taplo lint

.PHONY: lint
lint: fmt-check-ws fmt-check-toml lint-check-ws lint-check-codespell ## Runs all lints and checks for issues without trying to fix them.
	@echo "\n\033[36m======== OK: Lints and Formatting ========\033[0m\n"

.PHONY: lint-fix
lint-fix: fmt-toml fmt-ws lint-fix-ws lint-fix-codespell ## Runs all lints and applies fixes where possible.
	@echo "\n\033[36m======== OK: Lints and Formatting Fixes ========\033[0m\n"

.PHONY: rustdocs
rustdocs: ## Runs `cargo docs` to generate the Rust documents in the `target/doc` directory.
	RUSTDOCFLAGS="\
	--show-type-layout \
	--enable-index-page -Z unstable-options \
	-A rustdoc::private-doc-tests \
	-D warnings" \
	cargo doc \
	--workspace \
	--no-deps

.PHONY: test-doc
test-doc: ## Runs doctests on the workspace.
	cargo test --doc --workspace

.PHONY: test
test: ## Runs all tests in the workspace including unit and docs tests.
	make test-unit && \
	make test-doc

.PHONY: pr
pr: lint rustdocs test-doc test-unit  ## Runs lints (without fixing), audit, docs, and tests (run this before creating a PR).
	@echo "\n\033[36m======== CHECKS_COMPLETE ========\033[0m\n"
	@test -z "$$(git status --porcelain)" || echo "WARNNG: You have uncommitted changes"
	@echo "All good to create a PR!"


.PHONY: docker
docker: docker-down docker-up
	echo "Done!"
