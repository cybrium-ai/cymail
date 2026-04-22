use crate::EmailReport;
use colored::Colorize;
pub fn print_report(r: &EmailReport, format: &str) {
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(r).unwrap()),
        _ => {
            let gc = match r.grade.as_str() { "A" => r.grade.green().bold(), "B" => r.grade.green(), _ => r.grade.red().bold() };
            eprintln!("  {} {} — {}/100 Grade: {}\n", "RESULT".green().bold(), r.domain.white(), r.score, gc);
            let ok = |b: bool| if b { "✓".green().to_string() } else { "✗".red().to_string() };
            eprintln!("  SPF   {} {}", ok(r.spf.configured), r.spf.policy.as_deref().unwrap_or("-"));
            eprintln!("  DKIM  {} {}", ok(r.dkim.configured), r.dkim.policy.as_deref().unwrap_or("-"));
            eprintln!("  DMARC {} {}", ok(r.dmarc.configured), r.dmarc.policy.as_deref().unwrap_or("-"));
            if !r.findings.is_empty() { eprintln!(); for fi in &r.findings { eprintln!("  [{}] {}", fi.severity.to_uppercase(), fi.title); } }
        }
    }
}
