use rand::{rngs::OsRng, Rng};
use secp256k1::{SecretKey, SECP256K1};

use crate::sign_schnorr_sig;

#[derive(Debug, Clone)]
pub struct SchnorrSigInput {
    pub sig: [u8; 64],
    pub msg: [u8; 32],
    pub pk: [u8; 32],
    pub sk: [u8; 32],
}

impl SchnorrSigInput {
    pub fn new_random() -> Self {
        let msg: [u8; 32] = [(); 32].map(|_| OsRng.gen());

        let sk = SecretKey::new(&mut OsRng);
        let (pk, _) = sk.x_only_public_key(SECP256K1);

        let sk = *sk.as_ref();
        let pk = pk.serialize();

        let sig = sign_schnorr_sig(&msg, &sk);

        SchnorrSigInput { sig, msg, pk, sk }
    }
}
