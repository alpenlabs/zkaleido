use zkaleido::ZkVmEnv;
use zkaleido_logging::{debug, info, trace};

pub mod program;

pub fn process_fibonacci(zkvm: &impl ZkVmEnv) {
    let buf = zkvm.read_buf();
    let n = u32::from_le_bytes(buf.try_into().expect("invalid input length"));
    debug!(?n, "calculating fibonacci number");

    // Compute the n'th fibonacci number, using normal Rust code.
    let mut a: u32 = 0;
    let mut b: u32 = 1;
    for _ in 0..n {
        let mut c = a + b;
        c %= 7919; // Modulus to prevent overflow.
        a = b;
        b = c;
        trace!(%a, %b, %c, "iteration");
    }

    info!(%a, "fibonacci value output");

    // Write the output of the program.
    zkvm.commit_buf(&a.to_le_bytes());
}
