use std::{
    fs::{self},
    path::{Path, PathBuf},
};

use bincode::{deserialize, serialize};
use sha2::{Digest, Sha256};
use sp1_helper::{build_program_with_args, BuildArgs};
use sp1_sdk::{MockProver, Prover, SP1VerifyingKey};

fn main() {
    // String to accumulate the contents of methods.rs file
    // Start with the necessary use statements
    let mut methods_file_content = String::from(
        r#"
use once_cell::sync::Lazy;
use std::fs;
"#,
    );
    let sha2_contents = build_program("sha2-chain");
    let fibonacci_contents = build_program("fibonacci");

    methods_file_content.push_str(&sha2_contents);
    methods_file_content.push_str(&fibonacci_contents);

    // Write the accumulated methods_file_content to methods.rs in the output directory
    let out_dir = std::env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .expect("OUT_DIR environment variable is not set. Cannot determine output directory.");
    let methods_path = out_dir.join("methods.rs");
    fs::write(&methods_path, methods_file_content).unwrap_or_else(|e| {
        panic!(
            "Failed to write methods.rs file at {}: {}",
            methods_path.display(),
            e
        )
    });
}

fn build_program(program_name: &str) -> String {
    let features = {
        #[cfg(feature = "mock")]
        {
            vec!["mock".to_string()]
        }
        #[cfg(not(feature = "mock"))]
        {
            vec![]
        }
    };

    let build_args = BuildArgs {
        elf_name: format!("{}.elf", program_name),
        output_directory: "cache".to_owned(),
        features,
        ..Default::default()
    };

    // Build the program
    build_program_with_args(program_name, build_args);

    // Now, ensure cache validity
    ensure_cache_validity(program_name)
        .expect("Failed to ensure cache validity after building program_name");

    // Create contents to be written to the file
    let program_name_upper = format!(
        "GUEST_SP1_{}",
        program_name.to_uppercase().replace("-", "_")
    );
    let base_path = Path::new(program_name)
        .canonicalize()
        .expect("Cache directory not found");
    let base_path_str = base_path
        .to_str()
        .expect("Failed to convert path to string");

    let mut methods_file_content = String::new();
    let full_path_str = format!("{}/cache/{}", base_path_str, program_name);
    methods_file_content.push_str(&format!(
        r#"
pub static {0}_ELF: Lazy<Vec<u8>> = Lazy::new(||{{ fs::read("{1}.elf").expect("Cannot find ELF") }});
pub static {0}_PK: Lazy<Vec<u8>> = Lazy::new(||{{ fs::read("{1}.pk").expect("Cannot find PK") }});
pub static {0}_VK: Lazy<Vec<u8>> = Lazy::new(||{{ fs::read("{1}.vk").expect("Cannot find VK") }});
"#,            
program_name_upper, full_path_str
        ));

    methods_file_content
}

fn is_cache_valid(expected_id: &[u8; 32], paths: &[PathBuf; 4]) -> bool {
    // Check if any required files are missing
    if paths.iter().any(|path| !path.exists()) {
        return false;
    }

    // Attempt to read the saved ID
    let saved_id = match fs::read(&paths[1]) {
        Ok(data) => data,
        Err(_) => return false,
    };

    expected_id == saved_id.as_slice()
}

fn ensure_cache_validity(program: &str) -> Result<SP1VerifyingKey, String> {
    let cache_dir = format!("{}/cache", program);
    let paths = ["elf", "id", "vk", "pk"]
        .map(|file| Path::new(&cache_dir).join(format!("{}.{}", program, file)));

    // Attempt to read the ELF file
    let elf = fs::read(&paths[0])
        .map_err(|e| format!("Failed to read ELF file {}: {}", paths[0].display(), e))?;
    let elf_hash: [u8; 32] = Sha256::digest(&elf).into();

    if !is_cache_valid(&elf_hash, &paths) {
        // Cache is invalid, need to generate vk and pk
        let client = MockProver::new();
        let (pk, vk) = client.setup(&elf);

        fs::write(&paths[1], elf_hash)
            .map_err(|e| format!("Failed to write ID file {}: {}", paths[1].display(), e))?;

        fs::write(&paths[2], serialize(&vk).expect("VK serialization failed"))
            .map_err(|e| format!("Failed to write VK file {}: {}", paths[2].display(), e))?;

        fs::write(&paths[3], serialize(&pk).expect("PK serialization failed"))
            .map_err(|e| format!("Failed to write PK file {}: {}", paths[3].display(), e))?;

        Ok(vk)
    } else {
        // Cache is valid, read the VK
        let serialized_vk = fs::read(&paths[2])
            .map_err(|e| format!("Failed to read VK file {}: {}", paths[2].display(), e))?;
        let vk: SP1VerifyingKey =
            deserialize(&serialized_vk).map_err(|e| format!("VK deserialization failed: {}", e))?;
        Ok(vk)
    }
}
