use zkaleido::ZkVmEnv;

pub mod program;

pub fn process_fibonacci_composition(zkvm: &impl ZkVmEnv) {
    // Read the verification key of sha2-chain program
    let fib_vk: [u32; 8] = zkvm.read_serde();
    let valid_fib_no: u32 = zkvm.read_verified_serde(&fib_vk);
    zkvm.commit_serde(&valid_fib_no);
}
