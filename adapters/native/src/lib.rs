//! # zkaleido-native-adapter
//!
//! This crate provides native-mode implementations of the [`ZkVmEnv`](zkaleido::ZkVmEnv),
//! [`ZkVmHost`](zkaleido::ZkVmHost), and [`ZkVmInputBuilder`](zkaleido::ZkVmInputBuilder) traits,
//! allowing you to run a ZkVM-like environment without generating actual zero-knowledge proofs.
//!
//! In native mode, the proof statements are executed directly in Rust, producing the
//! **expected public values**. When proving, the adapter generates a **Schnorr signature**
//! over the public values instead of a zero-knowledge proof. This approach
//! bypasses the usual process of ELF generation and ZKP generation used by the ZkVM, making it
//! useful for:
//!
//! - **Local testing**: Quickly verify logic and expected outputs without the overhead of full
//!   proof generation.
//! - **Development and debugging**: Work on higher-level features of a ZkVM-based application
//!   before integrating a real ZKP backend.
//! - **Prototyping**: Get immediate feedback on how your code behaves in a ZkVM-like environment
//!   without implementing a complete proof system.

mod env;
mod host;
mod input;
mod proof;

pub use env::NativeMachine;
pub use host::NativeHost;
