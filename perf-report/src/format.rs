use num_format::{Locale, ToFormattedString};

use crate::report::ZkVmResults;

/// Renders the full performance report: one results table per zkVM.
pub fn render_report(results: &[ZkVmResults]) -> String {
    results
        .iter()
        .map(format_results)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Returns formatted results for one zkVM as a table.
pub fn format_results(results: &ZkVmResults) -> String {
    let mut table_text = String::new();
    table_text.push('\n');
    table_text.push_str("| program                | cycles      | gas         |\n");
    table_text.push_str("|------------------------|-------------|-------------|");

    for program in &results.results {
        table_text.push_str(&format!(
            "\n| {:<22} | {:>11} | {:>11} |",
            program.name,
            program.summary.cycles().to_formatted_string(&Locale::en),
            program
                .summary
                .gas()
                .map(|g| g.to_formatted_string(&Locale::en))
                .unwrap_or_else(|| "-".to_string()),
        ));
    }
    table_text.push('\n');

    format!("**{} Execution Results**\n {table_text}", results.zkvm)
}
