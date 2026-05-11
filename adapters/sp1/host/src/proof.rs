use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues, SP1PublicValues};
use sp1_verifier::{GROTH16_VK_BYTES, Groth16Bn254Proof};
use zkaleido::{
    DataFormatError, Mismatched, ProgramId, Proof, ProofMetadata, ProofReceipt,
    ProofReceiptWithMetadata, ProofType, PublicValues, ZkVm, ZkVmProofError,
};

/// Layout of the bytes stored in `ProofReceiptWithMetadata::receipt().proof()` for Groth16:
///   `[vkey_hash_tag(4) || exit_code(32) || vk_root(32) || proof_nonce(32) || gnark_proof_bytes]`
const VKEY_HASH_TAG_LEN: usize = 4;
const FR_BYTES: usize = 32;
const EXIT_CODE_OFFSET: usize = VKEY_HASH_TAG_LEN;
const VK_ROOT_OFFSET: usize = EXIT_CODE_OFFSET + FR_BYTES;
const PROOF_NONCE_OFFSET: usize = VK_ROOT_OFFSET + FR_BYTES;
const GNARK_PROOF_OFFSET: usize = PROOF_NONCE_OFFSET + FR_BYTES;

#[derive(Debug, Clone)]
pub struct SP1ProofReceipt {
    inner: SP1ProofWithPublicValues,
    program_id: ProgramId,
}

impl SP1ProofReceipt {
    pub fn new(inner: SP1ProofWithPublicValues, program_id: ProgramId) -> Self {
        Self { inner, program_id }
    }

    pub fn into_inner(self) -> SP1ProofWithPublicValues {
        self.inner
    }

    pub fn inner(&self) -> &SP1ProofWithPublicValues {
        &self.inner
    }

    pub fn program_id(&self) -> &ProgramId {
        &self.program_id
    }
}

impl AsRef<SP1ProofWithPublicValues> for SP1ProofReceipt {
    fn as_ref(&self) -> &SP1ProofWithPublicValues {
        &self.inner
    }
}

impl TryFrom<ProofReceiptWithMetadata> for SP1ProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: ProofReceiptWithMetadata) -> Result<Self, Self::Error> {
        SP1ProofReceipt::try_from(&value)
    }
}

impl TryFrom<&ProofReceiptWithMetadata> for SP1ProofReceipt {
    type Error = ZkVmProofError;
    fn try_from(value: &ProofReceiptWithMetadata) -> Result<Self, Self::Error> {
        let zkvm_in_proof = value.metadata().zkvm();
        if zkvm_in_proof != &ZkVm::SP1 {
            Err(Mismatched {
                expected: ZkVm::SP1,
                actual: *zkvm_in_proof,
            })?
        }

        let version_in_proof = value.metadata().version().to_string();
        let sp1_version = sp1_sdk::SP1_CIRCUIT_VERSION.to_string();
        if version_in_proof != sp1_version {
            Err(Mismatched {
                expected: sp1_version.clone(),
                actual: version_in_proof,
            })?
        }

        let public_values_bytes = value.receipt().public_values().as_bytes();
        let public_values = SP1PublicValues::from(public_values_bytes);
        let program_id = value.metadata().program_id().clone();
        let proof_bytes = value.receipt().proof().as_bytes();
        let proof = match value.metadata().proof_type() {
            ProofType::Core | ProofType::Compressed => bincode::deserialize(proof_bytes)
                .map_err(|e| ZkVmProofError::DataFormat(DataFormatError::Serde(e.to_string())))?,
            ProofType::Groth16 => SP1Proof::Groth16(reconstruct_groth16_bn254_proof(
                proof_bytes,
                public_values_bytes,
                &program_id,
            )?),
        };
        let proof_receipt = SP1ProofWithPublicValues {
            proof,
            public_values,
            sp1_version,
            tee_proof: None,
        };
        Ok(SP1ProofReceipt::new(proof_receipt, program_id))
    }
}

impl TryFrom<SP1ProofReceipt> for ProofReceiptWithMetadata {
    type Error = ZkVmProofError;
    fn try_from(value: SP1ProofReceipt) -> Result<Self, Self::Error> {
        let sp1_receipt = value.as_ref();

        // For Groth16, store the on-chain bytes (selector + proof) so consumers can verify
        // directly without reconstructing the SP1 proof type. For other variants, bincode
        // round-trips losslessly through `SP1Proof`.
        let (proof_bytes, proof_type) = match &sp1_receipt.proof {
            SP1Proof::Groth16(_) => (sp1_receipt.bytes(), ProofType::Groth16),
            SP1Proof::Core(_) => (sp1_proof_bincode(sp1_receipt)?, ProofType::Core),
            SP1Proof::Compressed(_) => (sp1_proof_bincode(sp1_receipt)?, ProofType::Compressed),
            SP1Proof::Plonk(_) => {
                return Err(ZkVmProofError::DataFormat(DataFormatError::Other(
                    "SP1Proof::Plonk is not supported by zkaleido".into(),
                )));
            }
        };

        let proof = Proof::new(proof_bytes);
        let public_values = PublicValues::new(sp1_receipt.public_values.to_vec());
        let receipt = ProofReceipt::new(proof, public_values);

        let sp1_version = sp1_sdk::SP1_CIRCUIT_VERSION.to_string();
        let metadata = ProofMetadata::new(
            ZkVm::SP1,
            value.program_id().clone(),
            sp1_version,
            proof_type,
        );

        Ok(ProofReceiptWithMetadata::new(receipt, metadata))
    }
}

fn sp1_proof_bincode(sp1_receipt: &SP1ProofWithPublicValues) -> Result<Vec<u8>, ZkVmProofError> {
    bincode::serialize(&sp1_receipt.proof)
        .map_err(|e| ZkVmProofError::DataFormat(DataFormatError::Serde(e.to_string())))
}

/// Rebuild an SP1 [`Groth16Bn254Proof`] from the bytes stored in
/// `ProofReceiptWithMetadata::receipt().proof()`.
///
/// The five `public_inputs` are reconstructed as decimal-string `Fr` elements, matching what
/// SP1's prover originally emitted:
///
/// * `[0] vkey_hash` — `BigUint::from_bytes_be(program_id)`, the program verifying-key hash carried
///   in [`ProgramId`].
/// * `[1] committed_values_digest` — `Sha256(public_values)` with the top 3 bits masked, computed
///   via [`SP1PublicValues::hash_bn254`] so it lines up with SP1's Solidity verifier convention.
/// * `[2] exit_code`, `[3] vk_root`, `[4] proof_nonce` — the three 32-byte fields embedded in
///   `proof_bytes` immediately after the 4-byte `vkey_hash` tag.
///
/// `encoded_proof` is the hex of the stored proof bytes with the 4-byte `vkey_hash` selector
/// stripped, matching SP1's expected layout of `exit_code(32) || vk_root(32) || proof_nonce(32)
/// || gnark_proof(256)`. `groth16_vkey_hash` is populated from [`GROTH16_VK_BYTES`]; `raw_proof`
/// is left at its default — it is not consumed by any verification path we use.
///
/// Verification of saved Groth16 receipts is expected to go through
/// [`zkaleido_sp1_groth16_verifier::SP1Groth16Verifier::verify`], which derives every public
/// input from the proof bytes plus `program_id` and `public_values` directly — see that function
/// for the full verification flow and the exact structure it expects in the proof bytes.
fn reconstruct_groth16_bn254_proof(
    proof_bytes: &[u8],
    public_values_bytes: &[u8],
    program_id: &ProgramId,
) -> Result<Groth16Bn254Proof, ZkVmProofError> {
    if proof_bytes.len() < GNARK_PROOF_OFFSET {
        return Err(ZkVmProofError::DataFormat(DataFormatError::Other(format!(
            "Groth16 proof bytes too short: got {}, need at least {GNARK_PROOF_OFFSET}",
            proof_bytes.len(),
        ))));
    }

    let exit_code = &proof_bytes[EXIT_CODE_OFFSET..EXIT_CODE_OFFSET + FR_BYTES];
    let vk_root = &proof_bytes[VK_ROOT_OFFSET..VK_ROOT_OFFSET + FR_BYTES];
    let proof_nonce = &proof_bytes[PROOF_NONCE_OFFSET..PROOF_NONCE_OFFSET + FR_BYTES];

    let pv_hash = SP1PublicValues::from(public_values_bytes).hash_bn254();

    let public_inputs = [
        BigUint::from_bytes_be(&program_id.0).to_string(),
        pv_hash.to_string(),
        BigUint::from_bytes_be(exit_code).to_string(),
        BigUint::from_bytes_be(vk_root).to_string(),
        BigUint::from_bytes_be(proof_nonce).to_string(),
    ];

    Ok(Groth16Bn254Proof {
        public_inputs,
        encoded_proof: hex::encode(&proof_bytes[VKEY_HASH_TAG_LEN..]),
        raw_proof: String::new(),
        groth16_vkey_hash: Sha256::digest(*GROTH16_VK_BYTES).into(),
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use zkaleido::ZkVmTypedVerifier;

    use super::*;
    use crate::{SP1Host, prover::block_on_async};

    #[test]
    fn groth16_round_trips_through_sp1_proof_receipt() {
        let proof_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../groth16-verifier/proofs/fibonacci_SP1_v6.1.0.proof.bin");
        let original = ProofReceiptWithMetadata::load(&proof_path).unwrap();
        assert_eq!(original.metadata().proof_type(), ProofType::Groth16);

        let sp1_receipt: SP1ProofReceipt = (&original).try_into().unwrap();
        assert!(matches!(sp1_receipt.inner().proof, SP1Proof::Groth16(_)));

        let round_tripped: ProofReceiptWithMetadata = sp1_receipt.try_into().unwrap();

        assert_eq!(
            round_tripped.receipt().proof().as_bytes(),
            original.receipt().proof().as_bytes()
        );
        assert_eq!(
            round_tripped.receipt().public_values().as_bytes(),
            original.receipt().public_values().as_bytes()
        );
        assert_eq!(round_tripped.metadata(), original.metadata());
    }

    #[test]
    #[ignore = "requires the fibonacci guest ELF to be prebuilt under artifacts/sp1/fibonacci/target/; not produced by the standard test pipeline"]
    fn groth16_reconstructed_proof_verifies() {
        let proof_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../groth16-verifier/proofs/fibonacci_SP1_v6.1.0.proof.bin");
        let original = ProofReceiptWithMetadata::load(&proof_path).unwrap();
        let sp1_receipt: SP1ProofReceipt = (&original).try_into().unwrap();

        let elf_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../artifacts/sp1/fibonacci/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/guest-sp1-fibonacci");
        let elf_bytes = fs::read(&elf_path).unwrap();

        let host = block_on_async(SP1Host::init(&elf_bytes));
        host.verify_inner(&sp1_receipt).unwrap();
    }
}
