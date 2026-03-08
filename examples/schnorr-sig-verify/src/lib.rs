pub mod input;
pub mod logic;
pub mod program;

use zkaleido::{ZkVmEnvSerde, ZkVmEnvSsz};

use crate::logic::verify_schnorr_sig_k256;

pub fn process_schnorr_sig_verify(zkvm: &impl ZkVmEnvSerde) {
    let sig: Vec<u8> = zkvm.read_ssz();
    let msg: [u8; 32] = zkvm.read_ssz();
    let pk: [u8; 32] = zkvm.read_ssz();

    let result = verify_schnorr_sig_k256(&sig.try_into().unwrap(), &msg, &pk);

    zkvm.commit_ssz(&result);
}
