use sha2_chain::process_sha2_chain;
use zkaleido_risc0_adapter::Risc0ZkVmEnv;

pub fn main() {
    process_sha2_chain(&Risc0ZkVmEnv)
}
