use std::str::FromStr;

pub mod fibonacci;
pub mod schnorr;
pub mod sha2;

#[derive(Debug)]
#[non_exhaustive]
pub enum TestProgram {
    Fibonacci,
    Sha2Chain,
    Schnorr,
}

impl FromStr for TestProgram {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "fibonacci" => Ok(TestProgram::Fibonacci),
            "sha2-chain" => Ok(TestProgram::Sha2Chain),
            "schnorr" => Ok(TestProgram::Schnorr),
            // Add more matches
            _ => Err(format!("unknown program: {}", s)),
        }
    }
}
