mod spf;
mod dkim;
mod dmarc;
mod scoring;
mod output;
mod discover;
mod hardware_rot;
mod attest;
mod reputation;

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
    /// Reputation + trust signals — DNSBL, BIMI, DANE, DNSSEC, SPF-lookup-count, DKIM hygiene (v0.3 — P2).
    Reputation {
        #[arg(short, long)]
        domain: String,
        #[arg(short = 'f', long, default_value = "text")]
        format: String,
        /// Skip DNSWL / trust-list lookups.
        #[arg(long)]
        no_trust: bool,
        /// Comma-separated DKIM selectors to probe in addition to defaults.
        #[arg(long, value_delimiter = ',')]
        dkim_selectors: Vec<String>,
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
        Commands::Reputation { domain, format, no_trust, dkim_selectors } => {
            print_banner();
            let mut opts = reputation::ReputationOpts::default();
            if no_trust { opts.include_trust = false; }
            opts.dkim_selectors.extend(dkim_selectors.into_iter().filter(|s| !s.trim().is_empty()));
            let r = reputation::run(&domain, &opts).await;
            print_reputation(&r, &format);
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

fn print_reputation(r: &reputation::ReputationReport, format: &str) {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
        return;
    }
    eprintln!("  \x1b[35m\x1b[1mReputation\x1b[0m  domain: \x1b[1m{}\x1b[0m  ({} ms)\n", r.domain, r.elapsed_ms);
    eprintln!("  Provider:  {} ({})", r.provider.vendor, r.provider.category);
    eprintln!("  DNSSEC:    {} (dnskey={}, ds={})",
        if r.dnssec.signed { "\x1b[32msigned\x1b[0m" } else { "\x1b[33munsigned\x1b[0m" },
        r.dnssec.dnskey_present, r.dnssec.ds_present);
    eprintln!("  BIMI:      {}",
        if r.bimi.configured { "\x1b[32mconfigured\x1b[0m" } else { "not configured" });
    eprintln!("  SPF lookups: {}/{}{}",
        r.spf_lookups.lookup_count, r.spf_lookups.limit,
        if r.spf_lookups.over_limit { "  \x1b[31m← OVER LIMIT (RFC 7208 §4.6.4)\x1b[0m" } else { "" });

    eprintln!("\n  \x1b[1mDNSBL\x1b[0m");
    if r.dnsbl.blacklisted_listings > 0 {
        eprintln!("    \x1b[31m{} blacklisted listings\x1b[0m, {} trust listings", r.dnsbl.blacklisted_listings, r.dnsbl.trust_listings);
    } else {
        eprintln!("    \x1b[32mclean\x1b[0m ({} blacklist queries, {} trust listings)", r.dnsbl.queries.iter().filter(|h| h.kind == "blacklist").count(), r.dnsbl.trust_listings);
    }
    for hit in &r.dnsbl.queries {
        if hit.listed {
            let mark = if hit.kind == "trust" { "\x1b[32m✓\x1b[0m" } else { "\x1b[31m✗\x1b[0m" };
            eprintln!("    {} {:<32} {:<16} {}", mark, hit.list, hit.target, hit.return_codes.join(","));
        }
    }

    eprintln!("\n  \x1b[1mDANE TLSA on MX\x1b[0m");
    if r.dane.is_empty() {
        eprintln!("    (no MX)");
    } else {
        for d in &r.dane {
            let mark = if d.present { "\x1b[32m✓\x1b[0m" } else { "✗" };
            eprintln!("    {} {}:25 — {}", mark, d.mx_host, if d.present { format!("{} records", d.records.len()) } else { "absent".into() });
        }
    }

    eprintln!("\n  \x1b[1mDKIM key hygiene\x1b[0m");
    if r.dkim_hygiene.is_empty() {
        eprintln!("    no responsive selectors");
    } else {
        for k in &r.dkim_hygiene {
            let color = match k.hygiene.as_str() {
                "ok"      => "\x1b[32m",
                "weak"    => "\x1b[33m",
                _         => "\x1b[31m",
            };
            eprintln!("    {:<10} {}{:<10}\x1b[0m {} bits ({})",
                k.selector, color, k.hygiene,
                k.key_bits.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
                k.algorithm.clone().unwrap_or_default());
            if let Some(i) = &k.issue { eprintln!("              \x1b[2m{}\x1b[0m", i); }
        }
    }
}
