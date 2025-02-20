//! Set mock mode

fn main() {
    // Tell Cargo to rerun this build script if ZKVM_MOCK_MODE changes.
    println!("cargo:rerun-if-env-changed=ZKVM_MOCK_MODE");

    if std::env::var("ZKVM_MOCK_MODE")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
    {
        std::env::set_var("SP1_PROVER", "mock");
    }
}
