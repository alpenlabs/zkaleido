use strata_zkvm::{ProofType, ZkVmEnv, ZkVmInputResult, ZkVmProver};

use crate::verify_schnorr_sig;

pub fn process_schnorr_sig(zkvm: &impl ZkVmEnv) {
    let sig = zkvm.read_buf();
    let msg: [u8; 32] = zkvm.read_serde();
    let pk: [u8; 32] = zkvm.read_serde();

    let result = verify_schnorr_sig(&sig.try_into().unwrap(), &msg, &pk);

    zkvm.commit_serde(&result);
}

pub struct SchnorrSigInput {
    pub sig: [u8; 64],
    pub msg: [u8; 32],
    pub pk: [u8; 32],
}

pub struct SchnorrSigProver;

impl ZkVmProver for SchnorrSigProver {
    type Input = SchnorrSigInput;
    type Output = bool;

    fn proof_type() -> ProofType {
        ProofType::Core
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: strata_zkvm::ZkVmInputBuilder<'a>,
    {
        B::new()
            .write_buf(&input.sig)?
            .write_serde(&input.msg)?
            .write_serde(&input.pk)?
            .build()
    }

    fn process_output<H>(
        public_values: &strata_zkvm::PublicValues,
    ) -> strata_zkvm::ZkVmResult<Self::Output>
    where
        H: strata_zkvm::ZkVmHost,
    {
        H::extract_serde_public_output(public_values)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use strata_native_zkvm_adapter::{NativeHost, NativeMachine};
    use strata_zkvm::ZkVmProver;

    use crate::sign_schnorr_sig;

    use super::*;
    use rand::{rngs::OsRng, Rng};
    use secp256k1::{SecretKey, SECP256K1};

    fn get_native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                process_schnorr_sig(zkvm);
                Ok(())
            })),
        }
    }

    #[test]
    fn test_native() {
        let msg: [u8; 32] = [(); 32].map(|_| OsRng.gen());

        let sk = SecretKey::new(&mut OsRng);
        let (pk, _) = sk.x_only_public_key(SECP256K1);

        let sk = *sk.as_ref();
        let pk = pk.serialize();

        let sig = sign_schnorr_sig(&msg, &sk);

        let input = SchnorrSigInput { sig, msg, pk };

        let host = get_native_host();
        let receipt = SchnorrSigProver::prove(&input, &host).unwrap();
        let output =
            SchnorrSigProver::process_output::<NativeHost>(receipt.public_values()).unwrap();
        assert!(output);
    }
}
