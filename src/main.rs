mod spf;
mod dkim;
mod dmarc;
mod scoring;
mod output;
mod discover;
mod hardware_rot;
mod attest;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "cymail", version, about = "Email security scanner — Cybrium AI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// SPF / DKIM / DMARC posture scan (platform compatibility — schema is locked).
    Scan {
        #[arg(short, long)]
        domain: String,
        #[arg(short = 'f', long, default_value = "text")]
        format: String,
    },
    /// Bulk-scan many domains from a newline-separated file.
    Bulk {
        #[arg(short = 'F', long)]
        file: String,
    },
    /// Discover email addresses, reputation, MX, catch-all flag (v0.2 — P1).
    Discover {
        #[arg(short, long)]
        domain: String,
        #[arg(short = 'f', long, default_value = "text")]
        format: String,
        /// Skip live SMTP RCPT TO + catch-all probes (faster, less accurate).
        #[arg(long)]
        no_smtp: bool,
        /// Skip EmailRep.io reputation lookups.
        #[arg(long)]
        no_reputation: bool,
        /// Comma-separated extra seed names to guess against.
        #[arg(long, value_delimiter = ',')]
        seed: Vec<String>,
    },
    /// Report this host's hardware root-of-trust (TPM / Secure Enclave) (v0.2).
    Attest {
        #[arg(short = 'f', long, default_value = "text")]
        format: String,
    },
    Version,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailReport {
    pub domain:     String,
    pub spf:        ProtoResult,
    pub dkim:       ProtoResult,
    pub dmarc:      ProtoResult,
    pub score:      u8,
    pub grade:      String,
    pub findings:   Vec<Finding>,
    pub scanned_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoResult {
    pub configured: bool,
    pub record:     Option<String>,
    pub policy:     Option<String>,
    pub issues:     Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id:          String,
    pub title:       String,
    pub severity:    String,
    pub description: String,
}

fn print_banner() {
    eprintln!(
        "\x1b[35m\n   ___  _   _  __  __    _    ___ _     \n  / __|| | | ||  \\/  |  /_\\  |_ _| |    \n | (__ | |_| || |\\/| | / _ \\  | || |__  \n  \\___| \\__, ||_|  |_|/_/ \\_\\|___|____|\n        |___/\n\x1b[0m"
    );
    eprintln!(
        "  \x1b[35m\x1b[1mcymail\x1b[0m v{} — \x1b[2mCybrium AI Email Scanner\x1b[0m\n",
        env!("CARGO_PKG_VERSION")
    );
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
                    eprintln!(
                        "  {} {} — {} {}/100",
                        if r.score >= 75 { "✓" } else { "✗" },
                        d, r.grade, r.score
                    );
                }
            }
        }
        Commands::Discover { domain, format, no_smtp, no_reputation, seed } => {
            print_banner();
            let mut opts = discover::DiscoverOpts::default();
            if no_smtp        { opts.use_smtp_validate = false; }
            if no_reputation  { opts.use_reputation    = false; }
            if !seed.is_empty() {
                opts.seed_names.extend(seed.into_iter().filter(|s| !s.trim().is_empty()));
            }
            let r = discover::run(&domain, &opts).await;
            print_discovery(&r, &format);
        }
        Commands::Attest { format } => {
            print_banner();
            let r = attest::attest();
            print_attestation(&r, &format);
        }
        Commands::Version => {
            println!("cymail {} — Cybrium AI Email Scanner", env!("CARGO_PKG_VERSION"));
        }
    }
}

async fn scan_domain(domain: &str) -> EmailReport {
    let s = spf::check(domain).await;
    let dk = dkim::check(domain).await;
    let dm = dmarc::check(domain).await;
    let (score, grade, findings) = scoring::calculate(&s, &dk, &dm);
    EmailReport {
        domain: domain.into(),
        spf: s, dkim: dk, dmarc: dm,
        score, grade, findings,
        scanned_at: chrono::Utc::now().to_rfc3339(),
    }
}

fn print_discovery(r: &discover::DiscoveryReport, format: &str) {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
        return;
    }
    eprintln!("  \x1b[35m\x1b[1mDiscovery\x1b[0m  domain: \x1b[1m{}\x1b[0m", r.domain);
    eprintln!("  MX hosts:  {}", if r.mx_hosts.is_empty() { "(none)".into() } else { r.mx_hosts.join(", ") });
    eprintln!("  Catch-all: {}", match r.catch_all {
        Some(true)  => "\x1b[33myes — SMTP validation results suppressed\x1b[0m",
        Some(false) => "\x1b[32mno\x1b[0m",
        None        => "(not probed)",
    });
    eprintln!("  Sources:   {}", r.sources_queried.join(", "));
    eprintln!("  Found:     {} addresses in {} ms\n", r.emails.len(), r.elapsed_ms);
    for em in &r.emails {
        let mark = match em.validated {
            Some(true)  => "\x1b[32m✓\x1b[0m",
            Some(false) => "\x1b[31m✗\x1b[0m",
            None        => " ",
        };
        let rep = em.reputation.as_ref().map(|x| {
            let badges: Vec<&str> = [
                x.blacklisted.unwrap_or(false).then_some("blacklisted"),
                x.malicious.unwrap_or(false).then_some("malicious"),
                x.credentials_leaked.unwrap_or(false).then_some("creds-leaked"),
                x.data_breach.unwrap_or(false).then_some("in-breach"),
                x.suspicious.unwrap_or(false).then_some("suspicious"),
            ].into_iter().flatten().collect();
            if badges.is_empty() { String::new() } else { format!(" \x1b[31m[{}]\x1b[0m", badges.join(",")) }
        }).unwrap_or_default();
        eprintln!("    {} {:<48} ({}){}", mark, em.address, em.source, rep);
    }
}

fn print_attestation(r: &attest::AttestationReport, format: &str) {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
        return;
    }
    eprintln!("  \x1b[35m\x1b[1mHost attestation\x1b[0m");
    eprintln!("  Host:    {}", r.host);
    eprintln!("  OS:      {} / {}", r.os, r.arch);
    eprintln!("  ROT:     {} ({})", r.root_of_trust.kind.as_str(), if r.root_of_trust.present { "present" } else { "absent" });
    if !r.root_of_trust.vendor.is_empty() {
        eprintln!("  Vendor:  {}", r.root_of_trust.vendor);
    }
}
