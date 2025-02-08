use schnorr_sig_verify::process_schnorr_sig_verify;
use zkaleido_risc0_adapter::Risc0ZkVmEnv;

pub fn main() {
    process_schnorr_sig_verify(&Risc0ZkVmEnv)
}
