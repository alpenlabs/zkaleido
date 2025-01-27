use schnorr_sig_verify::process_schnorr_sig;
use zkaleido_risc0_adapter::Risc0ZkVmEnv;

fn main() {
    process_schnorr_sig(&Risc0ZkVmEnv)
}
