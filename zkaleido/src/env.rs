#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "serde")]
use serde::{de::DeserializeOwned, Serialize};
#[cfg(feature = "ssz")]
use ssz::{Decode, Encode};

/// A trait representing a Zero-Knowledge Virtual Machine (ZkVM) interface.
/// Provides methods for reading inputs, committing outputs, and verifying proofs
/// within the ZkVM environment.
///
/// This base trait provides raw buffer operations. For typed serialization,
/// see the extension traits [`ZkVmEnvSerde`] (requires the `serde` feature),
/// [`ZkVmEnvBorsh`] (requires the `borsh` feature), and
/// [`ZkVmEnvSsz`] (requires the `ssz` feature).
pub trait ZkVmEnv {
    /// Reads a serialized byte buffer from the guest code.
    ///
    /// The input is expected to be written with [`write_buf`](crate::ZkVmInputBuilder::write_buf).
    fn read_buf(&self) -> Vec<u8>;

    /// Commits a pre-serialized buffer to the public values stream.
    ///
    /// This method is intended for cases where the data has already been serialized
    /// outside of the ZkVM's standard serialization methods. It allows you to provide
    /// serialized outputs directly, bypassing any further serialization.
    fn commit_buf(&self, raw_output: &[u8]);

    /// Verifies a proof generated with the ZkVM.
    ///
    /// This method checks the validity of the proof against the provided verification key digest
    /// and public values. It will panic if the proof fails to verify.
    fn verify_native_proof(&self, vk_digest: &[u32; 8], public_values: &[u8]);

    /// Reads and verifies a committed output from another guest function.
    ///
    /// This is equivalent to calling [`ZkVmEnv::read_buf`] and [`ZkVmEnv::verify_native_proof`],
    /// but avoids double serialization and deserialization. The function will panic if the
    /// proof fails to verify.
    fn read_verified_buf(&self, vk_digest: &[u32; 8]) -> Vec<u8> {
        let public_values_raw = self.read_buf();
        self.verify_native_proof(vk_digest, &public_values_raw);
        public_values_raw
    }
}

/// Extension trait for [`ZkVmEnv`] providing Serde serialization support.
///
/// This trait provides methods for reading and committing Serde-serializable types
/// within the ZkVM environment. Default implementations use `bincode` for
/// serialization/deserialization via the underlying buffer operations on [`ZkVmEnv`].
///
/// Adapters that use a different serialization protocol (e.g. SP1 and RISC0 guest
/// environments, which use VM-specific I/O) should override these methods.
#[cfg(feature = "serde")]
pub trait ZkVmEnvSerde: ZkVmEnv {
    /// Reads a serialized object from the guest code, deserializing it using Serde.
    ///
    /// The input is expected to be written with
    /// [`write_serde`](crate::ZkVmInputBuilder::write_serde).
    ///
    /// The default implementation reads a buffer via [`ZkVmEnv::read_buf`] and
    /// deserializes it using `bincode`.
    fn read_serde<T: DeserializeOwned>(&self) -> T {
        let buf = self.read_buf();
        bincode::deserialize(&buf).expect("bincode deserialization failed")
    }

    /// Commits a Serde-serializable object to the public values stream.
    ///
    /// Values that are committed can be proven as public parameters.
    ///
    /// The default implementation serializes using `bincode` and commits via
    /// [`ZkVmEnv::commit_buf`].
    fn commit_serde<T: Serialize>(&self, output: &T) {
        let bytes = bincode::serialize(output).expect("bincode serialization failed");
        self.commit_buf(&bytes);
    }

    /// Reads and verifies a committed output from another guest function, deserializing it using
    /// Serde.
    ///
    /// This function is meant to read the committed output of another guest function
    /// that was written with [`ZkVmEnvSerde::commit_serde`].
    /// It then verifies the proof against the given verification key digest.
    ///
    /// This is equivalent to calling [`ZkVmEnvSerde::read_serde`] and
    /// [`ZkVmEnv::verify_native_proof`], but avoids double serialization and deserialization.
    /// The function will panic if the proof fails to verify.
    ///
    /// The default implementation reads a verified buffer via [`ZkVmEnv::read_verified_buf`]
    /// and deserializes it using `bincode`.
    fn read_verified_serde<T: DeserializeOwned>(&self, vk_digest: &[u32; 8]) -> T {
        let verified_buf = self.read_verified_buf(vk_digest);
        bincode::deserialize(&verified_buf).expect("bincode deserialization failed")
    }
}

/// Extension trait for [`ZkVmEnv`] providing Borsh serialization support.
///
/// This trait provides methods for reading and committing Borsh-serializable types
/// within the ZkVM environment. Default implementations use `borsh` for
/// serialization/deserialization via the underlying buffer operations on [`ZkVmEnv`].
///
/// This trait is automatically implemented for all types that implement [`ZkVmEnv`]
/// when the `borsh` feature is enabled.
#[cfg(feature = "borsh")]
pub trait ZkVmEnvBorsh: ZkVmEnv {
    /// Reads a Borsh-serialized object from the guest code.
    ///
    /// The input is expected to be written with
    /// [`write_borsh`](`crate::ZkVmInputBuilder::write_borsh).
    fn read_borsh<T: BorshDeserialize>(&self) -> T {
        let buf = self.read_buf();
        borsh::from_slice(&buf).expect("borsh deserialization failed")
    }

    /// Commits a Borsh-serializable object to the public values stream.
    ///
    /// Values that are committed can be proven as public parameters.
    fn commit_borsh<T: BorshSerialize>(&self, output: &T) {
        self.commit_buf(&borsh::to_vec(output).expect("borsh serialization failed"));
    }

    /// Reads and verifies a committed output from another guest function, deserializing it using
    /// Borsh.
    ///
    /// This function is intended for guest commitments committed via
    /// [`ZkVmEnvBorsh::commit_borsh`]. The output is expected to be Borsh-serializable.
    /// It then verifies the proof using the internal verification key context.
    ///
    /// This is equivalent to calling [`ZkVmEnvBorsh::read_borsh`] and
    /// [`ZkVmEnv::verify_native_proof`], but avoids double serialization and deserialization.
    /// The function will panic if the proof fails to verify.
    fn read_verified_borsh<T: BorshDeserialize>(&self, vk_digest: &[u32; 8]) -> T {
        let verified_public_values_buf = self.read_verified_buf(vk_digest);
        borsh::from_slice(&verified_public_values_buf).expect("failed borsh deserialization")
    }
}

/// Blanket implementation of [`ZkVmEnvBorsh`] for all types that implement [`ZkVmEnv`].
#[cfg(feature = "borsh")]
impl<T: ZkVmEnv> ZkVmEnvBorsh for T {}

/// Extension trait for [`ZkVmEnv`] providing SSZ serialization support.
///
/// This trait provides methods for reading and committing SSZ-serializable types
/// within the ZkVM environment. Default implementations use `ssz` for
/// serialization/deserialization via the underlying buffer operations on [`ZkVmEnv`].
///
/// This trait is automatically implemented for all types that implement [`ZkVmEnv`]
/// when the `ssz` feature is enabled.
#[cfg(feature = "ssz")]
pub trait ZkVmEnvSsz: ZkVmEnv {
    /// Reads an SSZ-serialized object from the guest code.
    ///
    /// The input is expected to be written with
    /// [`write_ssz`](`crate::ZkVmInputBuilder::write_ssz).
    fn read_ssz<T: Decode>(&self) -> T {
        let buf = self.read_buf();
        T::from_ssz_bytes(&buf).expect("ssz deserialization failed")
    }

    /// Commits an SSZ-serializable object to the public values stream.
    ///
    /// Values that are committed can be proven as public parameters.
    fn commit_ssz<T: Encode>(&self, output: &T) {
        self.commit_buf(&output.as_ssz_bytes());
    }

    /// Reads and verifies a committed output from another guest function, deserializing it using
    /// SSZ.
    ///
    /// This function is intended for guest commitments committed via
    /// [`ZkVmEnvSsz::commit_ssz`]. The output is expected to be SSZ-serializable.
    /// It then verifies the proof using the internal verification key context.
    ///
    /// This is equivalent to calling [`ZkVmEnvSsz::read_ssz`] and
    /// [`ZkVmEnv::verify_native_proof`], but avoids double serialization and deserialization.
    /// The function will panic if the proof fails to verify.
    fn read_verified_ssz<T: Decode>(&self, vk_digest: &[u32; 8]) -> T {
        let verified_buf = self.read_verified_buf(vk_digest);
        T::from_ssz_bytes(&verified_buf).expect("ssz deserialization failed")
    }
}

/// Blanket implementation of [`ZkVmEnvSsz`] for all types that implement [`ZkVmEnv`].
#[cfg(feature = "ssz")]
impl<T: ZkVmEnv> ZkVmEnvSsz for T {}
