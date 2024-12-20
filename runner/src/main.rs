use programs::{fibonacci, TestProgram};

mod args;
mod programs;

use args::Args;

fn main() {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args: Args = argh::from_env();
    let programs = args.programs;

    for progam in programs {
        match progam {
            TestProgram::Fibonacci => {
                fibonacci::make_proofs();
            }
        }
    }
}
