use num_format::{Locale, ToFormattedString};

use crate::{
    diff::format_delta,
    payload::{ProgramPayload, ReportPayload, ZkVmPayload},
    report::ZkVmResults,
};

/// Renders the full performance report: one results table per zkVM, with
/// per-program delta columns against `baseline` when one is given.
pub fn render_report(results: &[ZkVmResults], baseline: Option<&ReportPayload>) -> String {
    results
        .iter()
        .map(|zkvm_results| {
            let zkvm_baseline =
                baseline.and_then(|payload| payload.zkvm(&zkvm_results.zkvm.to_string()));
            format_results(zkvm_results, zkvm_baseline)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Returns formatted results for one zkVM as a table, with delta columns
/// against `baseline` when one is given.
pub fn format_results(results: &ZkVmResults, baseline: Option<&ZkVmPayload>) -> String {
    let table_text = match baseline {
        Some(baseline) => format_table_with_deltas(results, baseline),
        None => format_table(results),
    };
    format!("**{} Execution Results**\n {table_text}", results.zkvm)
}

/// Builds the results table without a baseline to compare against.
fn format_table(results: &ZkVmResults) -> String {
    let mut table_text = String::new();
    table_text.push('\n');
    table_text.push_str("| program                | cycles      | gas         |\n");
    table_text.push_str("|------------------------|-------------|-------------|");

    for program in &results.results {
        table_text.push_str(&format!(
            "\n| {:<22} | {:>11} | {:>11} |",
            program.name,
            program.summary.cycles().to_formatted_string(&Locale::en),
            format_gas(program.summary.gas()),
        ));
    }
    table_text.push('\n');
    table_text
}

/// Builds the results table with delta columns against `baseline`.
fn format_table_with_deltas(results: &ZkVmResults, baseline: &ZkVmPayload) -> String {
    let mut table_text = String::new();
    table_text.push('\n');
    table_text.push_str(&format!(
        "| {:<22} | {:<11} | {:<11} | {:<20} | {:<20} |\n",
        "program", "cycles", "gas", "Δ cycles", "Δ gas"
    ));
    table_text.push_str(&format!(
        "|{:-<24}|{:-<13}|{:-<13}|{:-<22}|{:-<22}|",
        "", "", "", "", ""
    ));

    for program in &results.results {
        let baseline_program = baseline.program(&program.name);
        let cycles = program.summary.cycles();
        let gas = program.summary.gas();
        table_text.push_str(&format!(
            "\n| {:<22} | {:>11} | {:>11} | {:>20} | {:>20} |",
            program.name,
            cycles.to_formatted_string(&Locale::en),
            format_gas(gas),
            format_cycles_delta(cycles, baseline_program),
            format_gas_delta(gas, baseline_program),
        ));
    }
    table_text.push('\n');
    table_text
}

/// Formats an optional gas amount, `-` when the program reports none.
fn format_gas(gas: Option<u64>) -> String {
    gas.map(|gas| gas.to_formatted_string(&Locale::en))
        .unwrap_or_else(|| "-".to_string())
}

/// Formats the cycles delta column: `new` for programs the baseline does
/// not cover.
fn format_cycles_delta(cycles: u64, baseline: Option<&ProgramPayload>) -> String {
    match baseline {
        Some(baseline) => format_delta(cycles, baseline.cycles),
        None => "new".to_string(),
    }
}

/// Formats the gas delta column: `-` when the program reports no gas,
/// `new` when only the baseline is missing it.
fn format_gas_delta(gas: Option<u64>, baseline: Option<&ProgramPayload>) -> String {
    match (gas, baseline.and_then(|baseline| baseline.gas)) {
        (Some(gas), Some(baseline_gas)) => format_delta(gas, baseline_gas),
        (Some(_), None) => "new".to_string(),
        (None, _) => "-".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use zkaleido::{ExecutionSummary, PublicValues, ZkVm};

    use super::*;

    fn sample_results() -> ZkVmResults {
        ZkVmResults::new(
            ZkVm::SP1,
            vec![
                (
                    "fibonacci".to_string(),
                    ExecutionSummary::new(PublicValues::default(), 1_100, Some(220)),
                ),
                (
                    "sha2-chain".to_string(),
                    ExecutionSummary::new(PublicValues::default(), 900_000, None),
                ),
                (
                    "new-program".to_string(),
                    ExecutionSummary::new(PublicValues::default(), 42, Some(7)),
                ),
            ],
        )
    }

    fn sample_baseline() -> ReportPayload {
        ReportPayload {
            zkvms: vec![ZkVmPayload {
                zkvm: "SP1".to_string(),
                results: vec![
                    ProgramPayload {
                        name: "fibonacci".to_string(),
                        cycles: 1_000,
                        gas: Some(200),
                    },
                    ProgramPayload {
                        name: "sha2-chain".to_string(),
                        cycles: 1_000_000,
                        gas: None,
                    },
                ],
            }],
        }
    }

    #[test]
    fn renders_without_baseline() {
        let report = render_report(&[sample_results()], None);
        assert!(report.contains("**SP1 Execution Results**"));
        assert!(report.contains("| program                | cycles      | gas         |"));
        assert!(!report.contains("Δ cycles"));
    }

    #[test]
    fn renders_deltas_against_baseline() {
        let baseline = sample_baseline();
        let report = render_report(&[sample_results()], Some(&baseline));

        assert!(report.contains("Δ cycles"));
        assert!(report.contains("Δ gas"));
        // fibonacci: both cycles and gas went up 10% over the baseline.
        assert!(report.contains("+100 (+10.0%)"));
        assert!(report.contains("+20 (+10.0%)"));
        // sha2-chain: cycles went down, gas is not reported at all.
        assert!(report.contains("-100,000 (-10.0%)"));
        // new-program: absent from the baseline.
        assert!(report.contains("new"));
    }

    #[test]
    fn ignores_baseline_of_other_zkvm() {
        let mut baseline = sample_baseline();
        baseline.zkvms[0].zkvm = "Risc0".to_string();
        let report = render_report(&[sample_results()], Some(&baseline));
        assert!(!report.contains("Δ cycles"));
    }
}
