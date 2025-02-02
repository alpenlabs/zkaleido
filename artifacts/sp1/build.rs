use sp1_build::{build_program, build_program_with_args, BuildArgs};

fn main() {
    build_program("fibonacci");
    build_program("sha2-chain");
    build_program("schnorr-sig-verify");

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

    build_program_with_args("fibonacci-composition", build_args);
}
