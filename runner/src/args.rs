use argh::FromArgs;

use crate::programs::TestProgram;

/// Command-line arguments
#[derive(Debug, FromArgs)]
pub struct Args {
    #[argh(option, short = 'p', description = "programs to execute")]
    pub programs: Vec<TestProgram>,
}
