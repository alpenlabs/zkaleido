/// A proof report containing a performance stats about proof generation.
#[derive(Debug, Clone)]
pub struct ProofReport {
    pub name: String,
    pub cycles: u64,
    pub execution_time: u128,
    pub proving_time: u128,
}
