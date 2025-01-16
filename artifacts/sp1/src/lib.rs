use sp1_sdk::include_elf;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("guest-sp1-fibonacci");
pub const SHA2_CHAIN_ELF: &[u8] = include_elf!("guest-sha2-chain");
pub const SCHNORR_ELF: &[u8] = include_elf!("guest-schnorr");
