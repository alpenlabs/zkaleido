use fibonacci::process_fib;
use strata_risc0_adapter::Risc0ZkVmEnv;

fn main() {
    process_fib(&Risc0ZkVmEnv)
}
