use fibonacci::process_fibonacci;
use zkaleido_risc0_adapter::Risc0ZkVmEnv;

pub fn main() {
    process_fibonacci(&Risc0ZkVmEnv)
}
