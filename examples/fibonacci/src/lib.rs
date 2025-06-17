use zkaleido::ZkVmEnv;

pub mod program;

pub fn process_fibonacci(zkvm: &impl ZkVmEnv) {
    // Read an input to the program.
    let n: u32 = zkvm.read_serde();

    // Compute the n'th fibonacci number, using normal Rust code.
    let mut a: u32 = 0;
    let mut b: u32 = 1;
    for _ in 0..n {
        let mut c = a + b;
        c %= 7919; // Modulus to prevent overflow.
        a = b;
        b = c;
    }

    // Write the output of the program.
    zkvm.commit_serde(&a);
}
