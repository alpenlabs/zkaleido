use num_format::{Locale, ToFormattedString};

use crate::{PerformanceReport, args::EvalArgs};

/// Returns a formatted header for the performance report with basic PR data.
pub fn format_header(args: &EvalArgs) -> String {
    let mut detail_text = String::new();

    if args.post_to_gh {
        detail_text.push_str(&format!("*Commit*: {}\n", &args.commit_hash[..8]));
    } else {
        detail_text.push_str("*Local execution*\n");
    }

    detail_text
}

/// Returns formatted results for the [`PerformanceReport`]s shaped in a table.
pub fn format_results(results: &[PerformanceReport], host_name: String) -> String {
    let mut table_text = String::new();
    table_text.push('\n');
    table_text.push_str("| program                | cycles      | gas      |\n");
    table_text.push_str("|------------------------|-------------|----------|");

    for result in results.iter() {
        table_text.push_str(&format!(
            "\n| {:<22} | {:>11} | {:>8} |",
            result.name,
            result.cycles.to_formatted_string(&Locale::en),
            result.gas.unwrap_or(0).to_formatted_string(&Locale::en)
        ));
    }
    table_text.push('\n');

    format!("*{} Execution Results*\n {}", host_name, table_text)
}
