use num_format::{Locale, ToFormattedString};

/// Formats the change from `baseline` to `current` as e.g. `+1,234 (+5.6%)`.
///
/// The percentage is omitted when `baseline` is zero, and a zero change
/// renders as `0 (0.0%)`.
pub(crate) fn format_delta(current: u64, baseline: u64) -> String {
    let delta = i128::from(current) - i128::from(baseline);
    if delta == 0 {
        return "0 (0.0%)".to_string();
    }
    let sign = if delta < 0 { "-" } else { "+" };
    let magnitude = delta.unsigned_abs().to_formatted_string(&Locale::en);
    if baseline == 0 {
        return format!("{sign}{magnitude}");
    }
    let percent = delta as f64 / baseline as f64 * 100.0;
    format!("{sign}{magnitude} ({percent:+.1}%)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_increase() {
        assert_eq!(format_delta(1_100, 1_000), "+100 (+10.0%)");
    }

    #[test]
    fn formats_decrease() {
        assert_eq!(format_delta(900_000, 1_000_000), "-100,000 (-10.0%)");
    }

    #[test]
    fn formats_no_change() {
        assert_eq!(format_delta(1_000, 1_000), "0 (0.0%)");
    }

    #[test]
    fn omits_percent_for_zero_baseline() {
        assert_eq!(format_delta(500, 0), "+500");
    }
}
