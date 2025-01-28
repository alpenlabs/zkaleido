use zkaleido::{ProofType, ZkVmEnv, ZkVmInputResult, ZkVmProver};

pub fn process_fib(zkvm: &impl ZkVmEnv) {
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

pub struct FibProver;

impl ZkVmProver for FibProver {
    type Input = u32;
    type Output = u32;

    fn name() -> String {
        "fibonacci".to_owned()
    }

    fn proof_type() -> zkaleido::ProofType {
        ProofType::Compressed
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: zkaleido::ZkVmInputBuilder<'a>,
    {
        B::new().write_serde(input)?.build()
    }

    fn process_output<H>(
        public_values: &zkaleido::PublicValues,
    ) -> zkaleido::ZkVmResult<Self::Output>
    where
        H: zkaleido::ZkVmHost,
    {
        H::extract_serde_public_output(public_values)
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use zkaleido::ZkVmProver;
    use zkaleido_native_adapter::{NativeHost, NativeMachine};

    use super::process_fib;
    use crate::FibProver;

    pub fn get_native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                process_fib(zkvm);
                Ok(())
            })),
        }
    }

    #[test]
    fn test_native() {
        let input = 5;
        let host = get_native_host();
        let receipt = FibProver::prove(&input, &host).unwrap();
        let output = FibProver::process_output::<NativeHost>(receipt.public_values()).unwrap();
        assert_eq!(output, 5);
    }
}
