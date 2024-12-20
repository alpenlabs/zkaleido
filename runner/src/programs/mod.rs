use std::str::FromStr;

pub mod fibonacci;

#[derive(Debug)]
#[non_exhaustive]
pub enum TestProgram {
    Fibonacci,
}

impl FromStr for TestProgram {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "fibonacci" => Ok(TestProgram::Fibonacci),
            // Add more matches
            _ => Err(format!("unknown program: {}", s)),
        }
    }
}
