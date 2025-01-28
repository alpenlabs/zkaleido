// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use fibonacci_composition::process_fibonacci_composition;
use zkaleido_sp1_adapter::Sp1ZkVmEnv;

pub fn main() {
    process_fibonacci_composition(&Sp1ZkVmEnv)
}
