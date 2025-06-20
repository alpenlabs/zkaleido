pub mod input;
pub mod logic;
pub mod program;

use zkaleido::ZkVmEnv;

use crate::logic::verify_schnorr_sig_k256;

pub fn process_schnorr_sig_verify(zkvm: &impl ZkVmEnv) {
    let sig = zkvm.read_buf();
    let msg: [u8; 32] = zkvm.read_serde();
    let pk: [u8; 32] = zkvm.read_serde();

    let result = verify_schnorr_sig_k256(&sig.try_into().unwrap(), &msg, &pk);

    zkvm.commit_serde(&result);
}
