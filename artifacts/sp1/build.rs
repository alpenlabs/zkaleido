use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    let mut build_args = BuildArgs {
        ..Default::default()
    };

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

    build_program_with_args("fibonacci", build_args.clone());
    build_program_with_args("sha2-chain", build_args.clone());
    build_program_with_args("schnorr-sig-verify", build_args.clone());
    build_program_with_args("fibonacci-composition", build_args);
}
