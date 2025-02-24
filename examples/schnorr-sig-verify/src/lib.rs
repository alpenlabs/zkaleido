mod prover;
pub use prover::{process_schnorr_sig_verify, SchnorrSigProgram};

mod input;
pub use input::SchnorrSigInput;
use secp256k1::{schnorr::Signature, Keypair, Message, SecretKey, XOnlyPublicKey, SECP256K1};

pub fn sign_schnorr_sig(msg: &[u8; 32], sk: &[u8; 32]) -> [u8; 64] {
    let sk = SecretKey::from_slice(sk.as_ref()).expect("Invalid private key");
    let kp = Keypair::from_secret_key(SECP256K1, &sk);
    let msg = Message::from_digest_slice(msg.as_ref()).expect("Invalid message hash");
    let sig = SECP256K1.sign_schnorr(&msg, &kp);
    *sig.as_ref()
}

pub fn verify_schnorr_sig(sig: &[u8; 64], msg: &[u8; 32], pk: &[u8; 32]) -> bool {
    let msg = match Message::from_digest_slice(msg) {
        Ok(msg) => msg,
        Err(_) => return false,
    };

    let pk = match XOnlyPublicKey::from_slice(pk) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let sig = match Signature::from_slice(sig) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    sig.verify(&msg, &pk).is_ok()
}

pub fn verify_schnorr_sig_k256(sig: &[u8; 64], msg: &[u8; 32], pk: &[u8; 32]) -> bool {
    use k256::schnorr::{Signature, VerifyingKey};
    use signature::hazmat::PrehashVerifier;

    let sig = match Signature::try_from(sig.as_ref()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    let pk = match VerifyingKey::from_bytes(pk) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    pk.verify_prehash(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_schnorr_signature_pass() {
        let SchnorrSigInput { sk, pk, msg, sig } = SchnorrSigInput::new_random();

        let mut mod_msg = msg;
        mod_msg.swap(1, 2);

        assert!(verify_schnorr_sig(&sig, &msg, &pk));
        assert!(!verify_schnorr_sig(&sig, &mod_msg, &pk));

        let sig = sign_schnorr_sig(&mod_msg, &sk);
        let res = verify_schnorr_sig(&sig, &mod_msg, &pk);
        assert!(res);
    }

    #[test]
    fn test_schnorr_k256_signature_pass() {
        let SchnorrSigInput { sk, pk, msg, sig } = SchnorrSigInput::new_random();

        let mut mod_msg = msg;
        mod_msg.swap(1, 2);

        assert!(verify_schnorr_sig_k256(&sig, &msg, &pk));
        assert!(!verify_schnorr_sig_k256(&sig, &mod_msg, &pk));

        let sig = sign_schnorr_sig(&mod_msg, &sk);
        let res = verify_schnorr_sig_k256(&sig, &mod_msg, &pk);
        assert!(res);
    }
}
