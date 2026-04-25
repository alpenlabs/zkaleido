# Variables

profile := env("PROFILE", "release")
features := env("FEATURES", "")
programs := env("PROGRAMS", "groth16-verify-sp1")
zkvm := env("ZKVM", "risc0")
unit_test_args := "--locked --workspace -E 'kind(lib)' -E 'kind(bin)' -E 'kind(proc-macro)'"
cov_file := "lcov.info"

# Default recipe - show available commands
default:
    @just --list

# Build the workspace into the `target` directory
[group('build')]
build:
    cargo build --workspace --bin "zkaleido-runner" --features "{{ features }}" --profile "{{ profile }}"

# Run unit tests
[group('test')]
test-unit: ensure-cargo-nextest
    cargo nextest run {{ unit_test_args }}

# Run unit tests with coverage
[group('test')]
cov-unit: ensure-cargo-llvm-cov ensure-cargo-nextest
    rm -f {{ cov_file }}
    cargo llvm-cov nextest --lcov --output-path {{ cov_file }} {{ unit_test_args }}

# Generate an HTML coverage report and open it in the browser
[group('test')]
cov-report-html: ensure-cargo-llvm-cov ensure-cargo-nextest
    cargo llvm-cov --open --workspace --locked nextest

# Runs `nextest` under `cargo-mutants`. Caution: This can take *really* long to run
[group('test')]
mutants-test: ensure-cargo-mutants
    cargo mutants --workspace -j2

# Check for security advisories on any dependencies
[group('test')]
sec: ensure-cargo-audit
    cargo audit

# Generate proof report for programs for all supported ZKVMs
[group('prover')]
report: prover-clean
    ZKVM_MOCK=1 cargo run -p zkaleido-runner --release -- --programs "{{ programs }}"

# Generate SP1 proof report for given programs
[group('prover')]
report-sp1: prover-clean
    ZKVM_MOCK=1 cargo run -p zkaleido-runner --release --no-default-features -F sp1 -- --programs "{{ programs }}"

# Generate Risc0 proof report for given programs
[group('prover')]
report-risc0: prover-clean
    ZKVM_MOCK=1 cargo run -p zkaleido-runner --release --no-default-features -F risc0 -- --programs "{{ programs }}"

# Generate proof for the given program using the given ZKVM
[group('prover')]
proof:
    ZKVM_PROOF_DUMP=1 cargo run -p zkaleido-runner --release --no-default-features -F "{{ zkvm }}" -- --programs "{{ programs }}"

# Cleans up proofs and profiling data generated
[group('prover')]
prover-clean:
    rm -rf *.trace_profile
    rm -rf *.proof

# Check formatting issues but do not fix automatically
[group('code-quality')]
fmt-check-ws:
    cargo fmt --check

# Format source code in the workspace
[group('code-quality')]
fmt-ws:
    cargo fmt --all

# Check if cargo-audit is installed
[group('prerequisites')]
ensure-cargo-audit:
    #!/usr/bin/env bash
    if ! command -v cargo-audit &> /dev/null;
    then
        echo "cargo-audit not found. Please install it by running the command 'cargo install cargo-audit'"
        exit 1
    fi

# Check if cargo-llvm-cov is installed
[group('prerequisites')]
ensure-cargo-llvm-cov:
    #!/usr/bin/env bash
    if ! command -v cargo-llvm-cov &> /dev/null;
    then
        echo "cargo-llvm-cov not found. Please install it by running the command 'cargo install cargo-llvm-cov --locked'"
        exit 1
    fi

# Check if cargo-mutants is installed
[group('prerequisites')]
ensure-cargo-mutants:
    #!/usr/bin/env bash
    if ! command -v cargo-mutants &> /dev/null;
    then
        echo "cargo-mutants not found. Please install it by running the command 'cargo install cargo-mutants'"
        exit 1
    fi

# Check if cargo-nextest is installed
[group('prerequisites')]
ensure-cargo-nextest:
    #!/usr/bin/env bash
    if ! command -v cargo-nextest &> /dev/null;
    then
        echo "cargo-nextest not found. Please install it by running the command 'cargo install cargo-nextest --locked'"
        exit 1
    fi

# Check if taplo is installed
[group('prerequisites')]
ensure-taplo:
    #!/usr/bin/env bash
    if ! command -v taplo &> /dev/null; then
        echo "taplo not found. Please install it by following the instructions from: https://taplo.tamasfe.dev/cli/installation/binary.html"
        exit 1
    fi

# Check if codespell is installed
[group('prerequisites')]
ensure-codespell:
    #!/usr/bin/env bash
    if ! command -v codespell &> /dev/null; then
        echo "codespell not found. Please install it by running the command 'pip install codespell' or refer to the following link for more information: https://github.com/codespell-project/codespell"
        exit 1
    fi

# Runs `taplo` to check that TOML files are properly formatted
[group('code-quality')]
fmt-check-toml: ensure-taplo
    taplo fmt --check

# Runs `taplo` to format TOML files
[group('code-quality')]
fmt-toml: ensure-taplo
    taplo fmt

# Checks for lint issues in the workspace
[group('code-quality')]
lint-check-ws:
    #!/usr/bin/env bash
    set -euo pipefail
    for dir in examples adapters; do
        find "${dir}" -type f -name "Cargo.toml" -exec sh -c \
            'f="$1"; echo "Clippy for ${f}" && cargo clippy --manifest-path "${f}" --all-features -- -D warnings' shell {} \;
    done

# Lints the workspace and applies fixes where possible
[group('code-quality')]
lint-fix-ws:
    #!/usr/bin/env bash
    set -euo pipefail
    for dir in examples adapters; do
        find "${dir}" -type f -name "Cargo.toml" -exec sh -c \
            'f="$1"; echo "Clippy for ${f}" && cargo clippy --manifest-path "${f}" --all-features --fix -- -D warnings' shell {} \;
    done

# Runs `codespell` to check for spelling errors
[group('code-quality')]
lint-check-codespell: ensure-codespell
    codespell

# Runs `codespell` to fix spelling errors if possible
[group('code-quality')]
lint-fix-codespell: ensure-codespell
    codespell -w

# Lints TOML files
[group('code-quality')]
lint-check-toml: ensure-taplo
    taplo lint

# Runs all lints and checks for issues without trying to fix them
[group('code-quality')]
lint: fmt-check-ws fmt-check-toml lint-check-ws lint-check-codespell
    @echo "\n\033[36m======== OK: Lints and Formatting ========\033[0m\n"

# Runs all lints and applies fixes where possible
[group('code-quality')]
lint-fix: fmt-toml fmt-ws lint-fix-ws lint-fix-codespell
    @echo "\n\033[36m======== OK: Lints and Formatting Fixes ========\033[0m\n"

# Runs `cargo docs` to generate the Rust documents in the `target/doc` directory
[group('code-quality')]
rustdocs:
    RUSTDOCFLAGS="\
    --show-type-layout \
    --enable-index-page -Z unstable-options \
    -A rustdoc::private-doc-tests \
    -D warnings" \
    cargo doc \
    --workspace \
    --no-deps

# Runs doctests on the workspace
[group('code-quality')]
test-doc:
    cargo test --doc --workspace

# Runs all tests in the workspace including unit and docs tests
[group('code-quality')]
test: test-unit test-doc

# Runs lints (without fixing), docs, and tests (run this before creating a PR)
[group('code-quality')]
pr: lint rustdocs test-doc test-unit
    @echo "\n\033[36m======== CHECKS_COMPLETE ========\033[0m\n"
    @test -z "`git status --porcelain`" || echo "WARNING: You have uncommitted changes"
    @echo "All good to create a PR!"
