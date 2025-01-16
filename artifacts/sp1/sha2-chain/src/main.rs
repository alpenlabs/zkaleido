// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2_chain::process_sha_chain;
use strata_sp1_adapter::Sp1ZkVmEnv;

pub fn main() {
    process_sha_chain(&Sp1ZkVmEnv)
}
