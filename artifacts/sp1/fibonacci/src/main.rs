// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use fibonacci::process_fib;
use strata_sp1_adapter::Sp1ZkVmEnv;

pub fn main() {
    process_fib(&Sp1ZkVmEnv)
}
