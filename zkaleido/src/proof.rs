use std::{
    fs::File,
    io::{Read as _, Write as _},
    path::Path,
};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{ZkVm, ZkVmError, ZkVmResult};

/// Macro to define a newtype wrapper around `Vec<u8>` with common implementations.
macro_rules! define_byte_wrapper {
    ($name:ident) => {
        /// A type wrapping a [`Vec<u8>`] with common trait implementations,
        /// allowing easy serialization, comparison, and other utility operations.
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
        #[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
        #[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Creates a new instance from a `Vec<u8>`.
            pub fn new(data: Vec<u8>) -> Self {
                Self(data)
            }

            /// Returns a reference to the inner byte slice.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Consumes the wrapper and returns the inner `Vec<u8>`.
            pub fn into_inner(self) -> Vec<u8> {
                self.0
            }

            /// Checks if the byte vector is empty.
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl From<$name> for Vec<u8> {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl From<&$name> for Vec<u8> {
            fn from(value: &$name) -> Self {
                value.0.clone()
            }
        }

        impl From<&[u8]> for $name {
            fn from(value: &[u8]) -> Self {
                Self(value.to_vec())
            }
        }
    };
}

// Use the macro to define the specific types.
define_byte_wrapper!(Proof);
define_byte_wrapper!(PublicValues);
define_byte_wrapper!(VerifyingKey);

/// Summary of executing a zkVM program.
///
/// Contains the public output values from the execution along with execution performance metrics
/// such as cycle count and optional gas usage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct ExecutionSummary {
    /// The public values produced by the execution.
    public_values: PublicValues,
    /// The number of cycles consumed during execution.
    cycles: u64,
    /// Gas consumed during execution, if applicable.
    gas: Option<u64>,
}

impl ExecutionSummary {
    /// Creates a new `ExecutionResult` with the given public values, cycles, and optional gas.
    pub fn new(public_values: PublicValues, cycles: u64, gas: Option<u64>) -> Self {
        Self {
            public_values,
            cycles,
            gas,
        }
    }

    /// Returns the public values produced by the execution.
    pub fn public_values(&self) -> &PublicValues {
        &self.public_values
    }

    /// Returns the number of cycles consumed during execution.
    pub fn cycles(&self) -> u64 {
        self.cycles
    }

    /// Returns the gas consumed during execution, if applicable.
    pub fn gas(&self) -> Option<u64> {
        self.gas
    }

    /// Consumes the `ExecutionResult` and returns the public values.
    pub fn into_public_values(self) -> PublicValues {
        self.public_values
    }
}

/// A receipt containing a `Proof` and associated `PublicValues`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct ProofReceipt {
    /// The validity proof.
    proof: Proof,
    /// The public values associated with the proof.
    public_values: PublicValues,
}

impl ProofReceipt {
    /// Creates a new `ProofReceipt` from proof and it's associated public values
    pub fn new(proof: Proof, public_values: PublicValues) -> Self {
        Self {
            proof,
            public_values,
        }
    }

    /// Returns the validity proof
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// Returns the public values associated with the proof.
    pub fn public_values(&self) -> &PublicValues {
        &self.public_values
    }
}

/// Metadata associated with a proof.
///
/// Contains information about the ZKVM that generated the proof and the version of the proving
/// system used. This metadata is essential for proof verification, compatibility checking, and
/// debugging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct ProofMetadata {
    /// The zero-knowledge virtual machine that generated this proof.
    zkvm: ZkVm,
    /// Version string of the ZKVM
    version: String,
}

impl ProofMetadata {
    /// Creates new proof metadata.
    pub fn new(zkvm: ZkVm, version: impl Into<String>) -> Self {
        Self {
            zkvm,
            version: version.into(),
        }
    }

    /// Returns the ZKVM that generated this proof.
    pub fn zkvm(&self) -> &ZkVm {
        &self.zkvm
    }

    /// Returns the version string of the proving system.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// A receipt containing a `Proof` and associated `PublicValues`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct ProofReceiptWithMetadata {
    /// The validity proof receipt.
    receipt: ProofReceipt,
    /// ZKVM used to generate this proof
    metadata: ProofMetadata,
}

impl ProofReceiptWithMetadata {
    /// Creates new proof receipt with metadata.
    pub fn new(receipt: ProofReceipt, metadata: ProofMetadata) -> Self {
        Self { receipt, metadata }
    }

    /// Returns the reference to the proof receipt
    pub fn receipt(&self) -> &ProofReceipt {
        &self.receipt
    }

    /// Returns the metadata of the proof
    pub fn metadata(&self) -> &ProofMetadata {
        &self.metadata
    }

    /// Encodes the receipt into a binary format.
    ///
    /// Layout: `[proof_len: u64 LE][proof][pv_len: u64 LE][public_values][zkvm: u8][ver_len: u64
    /// LE][version]`
    pub fn encode(&self) -> Vec<u8> {
        let proof = self.receipt.proof.as_bytes();
        let pv = self.receipt.public_values.as_bytes();
        let zkvm_tag = self.metadata.zkvm as u8;
        let version = self.metadata.version().as_bytes();

        let capacity = 8 + proof.len() + 8 + pv.len() + 1 + 8 + version.len();
        let mut buf = Vec::with_capacity(capacity);

        buf.extend_from_slice(&(proof.len() as u64).to_le_bytes());
        buf.extend_from_slice(proof);
        buf.extend_from_slice(&(pv.len() as u64).to_le_bytes());
        buf.extend_from_slice(pv);
        buf.push(zkvm_tag);
        buf.extend_from_slice(&(version.len() as u64).to_le_bytes());
        buf.extend_from_slice(version);

        buf
    }

    /// Decodes a receipt from the binary format produced by [`encode`](Self::encode).
    pub fn decode(mut data: &[u8]) -> ZkVmResult<Self> {
        let err = || ZkVmError::Other("unexpected end of data".into());

        let read_bytes = |d: &mut &[u8]| -> ZkVmResult<Vec<u8>> {
            let (len_bytes, rest) = d.split_at_checked(8).ok_or_else(err)?;
            let len = u64::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
            let (payload, rest) = rest.split_at_checked(len).ok_or_else(err)?;
            *d = rest;
            Ok(payload.to_vec())
        };

        let proof = read_bytes(&mut data)?;
        let public_values = read_bytes(&mut data)?;
        let (&zkvm_tag, rest) = data.split_first().ok_or_else(err)?;
        data = rest;
        let version_bytes = read_bytes(&mut data)?;

        Ok(Self {
            receipt: ProofReceipt {
                proof: Proof::new(proof),
                public_values: PublicValues::new(public_values),
            },
            metadata: ProofMetadata {
                zkvm: ZkVm::try_from(zkvm_tag)?,
                version: String::from_utf8(version_bytes)
                    .map_err(|e| ZkVmError::Other(format!("invalid utf-8 in version: {e}")))?,
            },
        })
    }

    /// Saves the proof to a file named `{program_name}_{zkvm}_{version}.proof`.
    pub fn save(&self, program_name: impl AsRef<str>) -> ZkVmResult<()> {
        let filename = format!(
            "{}_{}_{}.proof",
            program_name.as_ref(),
            self.metadata.zkvm(),
            self.metadata.version()
        );
        let mut file = File::create(filename).expect("failed to create file");
        file.write_all(&self.encode())
            .map_err(|e| ZkVmError::Other(format!("failed to write proof: {e}")))
    }

    /// Loads a proof from a path.
    pub fn load(path: impl AsRef<Path>) -> ZkVmResult<Self> {
        let mut file = File::open(path).expect("failed to open file");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|e| ZkVmError::Other(format!("failed to read proof: {e}")))?;
        Self::decode(&buf)
    }
}

/// An input to the aggregation program.
///
/// Consists of a [`ProofReceipt`] and a [`VerifyingKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregationInput {
    /// The proof receipt containing the proof and its public values.
    receipt: ProofReceiptWithMetadata,
    /// The verification key for validating the proof.
    vk: VerifyingKey,
}

impl AggregationInput {
    /// Creates a new `AggregationInput`.
    pub fn new(receipt: ProofReceiptWithMetadata, vk: VerifyingKey) -> Self {
        Self { receipt, vk }
    }

    /// Returns a reference to the `ProofReceipt`.
    pub fn receipt(&self) -> &ProofReceiptWithMetadata {
        &self.receipt
    }

    /// Returns a reference to the `VerifyingKey`.
    pub fn vk(&self) -> &VerifyingKey {
        &self.vk
    }
}

/// Commitment of the [`VerifyingKey`]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct VerifyingKeyCommitment([u32; 8]);

impl VerifyingKeyCommitment {
    /// Creates a new instance from a `Vec<u8>`.
    pub fn new(data: [u32; 8]) -> Self {
        Self(data)
    }

    /// Consumes the wrapper and returns the inner [u32; 8].
    pub fn into_inner(self) -> [u32; 8] {
        self.0
    }
}

/// Enumeration of proof types supported by the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum ProofType {
    /// Represents a Groth16 proof.
    Groth16,
    /// Represents a core proof.
    Core,
    /// Represents a compressed proof.
    Compressed,
}

#[cfg(test)]
mod tests {
    use arbitrary::{Arbitrary, Unstructured};

    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let mut u = Unstructured::new(b"seed data for arbitrary!!");
        let original = ProofReceiptWithMetadata::arbitrary(&mut u).unwrap();
        let decoded = ProofReceiptWithMetadata::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }
}
