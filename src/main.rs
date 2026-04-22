mod spf; mod dkim; mod dmarc; mod scoring; mod output;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "cymail", version, about = "Email security scanner — Cybrium AI")]
struct Cli { #[command(subcommand)] command: Commands }
#[derive(Subcommand)]
enum Commands {
    Scan { #[arg(short, long)] domain: String, #[arg(short = 'f', long, default_value = "text")] format: String },
    Bulk { #[arg(short = 'F', long)] file: String },
    Version,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailReport { pub domain: String, pub spf: ProtoResult, pub dkim: ProtoResult, pub dmarc: ProtoResult, pub score: u8, pub grade: String, pub findings: Vec<Finding>, pub scanned_at: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoResult { pub configured: bool, pub record: Option<String>, pub policy: Option<String>, pub issues: Vec<String> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding { pub id: String, pub title: String, pub severity: String, pub description: String }

fn print_banner() {
    eprintln!("\x1b[35m\n   ___  _   _  __  __    _    ___ _     \n  / __|| | | ||  \\/  |  /_\\  |_ _| |    \n | (__ | |_| || |\\/| | / _ \\  | || |__  \n  \\___| \\__, ||_|  |_|/_/ \\_\\|___|____|\n        |___/\n\x1b[0m");
    eprintln!("  \x1b[35m\x1b[1mcymail\x1b[0m v{} — \x1b[2mCybrium AI Email Scanner\x1b[0m\n", env!("CARGO_PKG_VERSION"));
}
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { domain, format } => {
            print_banner();
            let r = scan_domain(&domain).await;
            output::print_report(&r, &format);
        }
        Commands::Bulk { file } => {
            print_banner();
            if let Ok(c) = std::fs::read_to_string(&file) {
                for d in c.lines().filter(|l| !l.trim().is_empty()) {
                    let r = scan_domain(d.trim()).await;
                    eprintln!("  {} {} — {} {}/100", if r.score >= 75 { "✓" } else { "✗" }, d, r.grade, r.score);
                }
            }
        }
        Commands::Version => println!("cymail {} — Cybrium AI Email Scanner", env!("CARGO_PKG_VERSION")),
    }
}
async fn scan_domain(domain: &str) -> EmailReport {
    let s = spf::check(domain).await;
    let dk = dkim::check(domain).await;
    let dm = dmarc::check(domain).await;
    let (score, grade, findings) = scoring::calculate(&s, &dk, &dm);
    EmailReport { domain: domain.into(), spf: s, dkim: dk, dmarc: dm, score, grade, findings, scanned_at: chrono::Utc::now().to_rfc3339() }
}
