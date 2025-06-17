use sp1_sdk::include_elf;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("guest-sp1-fibonacci");
pub const FIBONACCI_COMPOSITION_ELF: &[u8] = include_elf!("guest-sp1-fibonacci-composition");
pub const SHA2_CHAIN_ELF: &[u8] = include_elf!("guest-sp1-sha2-chain");
pub const SCHNORR_SIG_VERIFY_ELF: &[u8] = include_elf!("guest-sp1-schnorr-sig-verify");
pub const GROTH16_VERIFY_SP1_ELF: &[u8] = include_elf!("guest-sp1-groth16-verify-sp1");
pub const GROTH16_VERIFY_RISC0_ELF: &[u8] = include_elf!("guest-sp1-groth16-verify-risc0");
