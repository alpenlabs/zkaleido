use std::{fs::File, path::Path};

use arbitrary::Arbitrary;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{ZkVm, ZkVmError, ZkVmResult};

/// Macro to define a newtype wrapper around `Vec<u8>` with common implementations.
macro_rules! define_byte_wrapper {
    ($name:ident) => {
        /// A type wrapping a [`Vec<u8>`] with common trait implementations,
        /// allowing easy serialization, comparison, and other utility operations.
        #[derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            BorshSerialize,
            BorshDeserialize,
            PartialEq,
            Eq,
            Arbitrary,
            Default,
        )]
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

/// A receipt containing a `Proof` and associated `PublicValues`.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Arbitrary,
    Default,
)]
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
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Arbitrary,
    Default,
)]
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
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Arbitrary,
    Default,
)]
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

    /// Saves the proof to a path.
    pub fn save(&self, path: impl AsRef<Path>) -> ZkVmResult<()> {
        bincode::serialize_into(File::create(path).expect("failed to open file"), self)
            .map_err(|e| ZkVmError::InvalidProofReceipt(e.into()))
    }

    /// Loads a proof from a path.
    pub fn load(path: impl AsRef<Path>) -> ZkVmResult<Self> {
        bincode::deserialize_from(File::open(path).expect("failed to open file"))
            .map_err(|e| ZkVmError::InvalidProofReceipt(e.into()))
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
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Arbitrary,
    Default,
)]
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
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Arbitrary,
)]
pub enum ProofType {
    /// Represents a Groth16 proof.
    Groth16,
    /// Represents a core proof.
    Core,
    /// Represents a compressed proof.
    Compressed,
}
