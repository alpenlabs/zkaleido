// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use schnorr::process_schnorr_sig;
use strata_sp1_adapter::Sp1ZkVmEnv;

pub fn main() {
    process_schnorr_sig(&Sp1ZkVmEnv);
}
