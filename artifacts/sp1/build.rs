use std::{
    env, fs,
    path::{Path, PathBuf},
};

use cargo_metadata::MetadataCommand;
use sp1_helper::{build_program_with_args, BuildArgs};
use sp1_sdk::{HashableKey, ProverClient};
use tera::{Context, Tera};

fn main() {
    // `CARGO_MANIFEST_DIR` points to artifacts/sp1/, so go up two levels to reach the project root.
    let manifest_dir =
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env variable not set");
    let examples_dir = Path::new(&manifest_dir)
        .parent() // goes to artifacts/
        .unwrap()
        .parent() // goes to project root
        .unwrap()
        .join("examples");

    // Read the directory entries in examples.
    let entries = fs::read_dir(&examples_dir)
        .unwrap_or_else(|err| panic!("Failed to read {:?}: {}", examples_dir, err));

    let mut build_args = BuildArgs {
        ..Default::default()
    };

    build_args.docker = true;
    build_args.workspace_directory = Some("../../".to_owned());

    build_args.features = {
        #[cfg(feature = "mock")]
        {
            vec!["mock".to_string()]
        }
        #[cfg(not(feature = "mock"))]
        {
            vec![]
        }
    };

    println!("Directories in '{}':", examples_dir.display());
    let mut vkeys = Vec::new();
    for entry in entries {
        let entry = entry.expect("Failed to get directory entry");
        let path = entry.path();

        // Check if the entry is a directory.
        if path.is_dir() {
            // Print only the directory name.
            if let Some(dir_name) = path.file_name() {
                let program_dir = dir_name.to_string_lossy().into_owned();
                build_from_templates(&program_dir);
                println!("built from template{:?}", program_dir);
                build_program_with_args(&program_dir, build_args.clone());
                println!("built sp1{:?}", program_dir);
                let vkey = get_vkey(&program_dir);
                vkeys.push((program_dir, vkey));
            }
        }
    }

    // Save the verifying keys to a file.
    let vkeys_path = examples_dir.join("vkeys.json");
    let vkeys_json =
        serde_json::to_string_pretty(&vkeys).expect("Failed to serialize verifying keys");
    fs::write(&vkeys_path, vkeys_json).expect("Failed to write verifying keys to file");
}

fn build_from_templates(program_dir: &str) {
    // Tell Cargo to re-run the build script if anything in the templates/ folder changes.
    println!("cargo:rerun-if-changed=templates/");

    let program = program_dir.replace("-", "_");

    // Create the necessary directories (e.g. generated_project/src).
    fs::create_dir_all(format!("{}/src", program_dir))
        .expect("Failed to create output directories");

    // Initialize Tera by loading all .tera templates from the templates folder.
    let tera = match Tera::new("templates/**/*.tera") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Parsing error(s): {}", e);
            std::process::exit(1)
        }
    };

    // Create a Tera context and insert variables for use in the templates.
    let mut context = Context::new();
    context.insert("version", "0.1.0");
    context.insert("edition", "2021");
    context.insert("program", &program);
    context.insert("program_dir", &program_dir);

    // Render the Cargo.toml template.
    let cargo_toml_content = tera
        .render("Cargo.toml.tera", &context)
        .expect("Failed to render Cargo.toml template");
    fs::write(format!("{}/Cargo.toml", program_dir), cargo_toml_content)
        .expect("Failed to write Cargo.toml");

    // Render the main.rs template.
    let main_rs_content = tera
        .render("src/main.rs.tera", &context)
        .expect("Failed to render main.rs template");
    fs::write(format!("{}/src/main.rs", program_dir), main_rs_content)
        .expect("Failed to write main.rs");

    println!("Generated Rust project in '{}'", program_dir);
}

fn get_vkey(program: &str) -> String {
    eprintln!("Generating verifying key for program '{}'", program);
    // Get the build directory from the environment
    let sp1_build_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set"));

    // Form the path to the program directory
    let program_path = sp1_build_dir.join(program);

    // Fetch metadata for this program
    let metadata = MetadataCommand::new()
        .manifest_path(program_path.join("Cargo.toml"))
        .exec()
        .expect("Failed to get metadata");

    // Use the root package name as the built ELF name
    let built_elf_name = metadata
        .root_package()
        .expect("Failed to get root package")
        .name
        .clone();

    // Source path: program/target/elf-compilation/.../release/{built_elf_name}
    let built_elf_path = program_path
        .join("target")
        .join("elf-compilation")
        .join("docker")
        .join("riscv32im-succinct-zkvm-elf")
        .join("release")
        .join(&built_elf_name);

    let elf = fs::read(&built_elf_path).unwrap();
    let prover_client = ProverClient::from_env();
    let (_, vk) = prover_client.setup(&elf);

    vk.bytes32()
}
