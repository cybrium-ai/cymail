mod spf;
mod dkim;
mod dmarc;
mod scoring;
mod output;
mod discover;
mod hardware_rot;
mod attest;
mod reputation;
mod reputation_ext;
mod leak;
mod ct_stream;
mod feeds;
mod bimi;
mod export;
mod scan;
mod server;
mod update;
mod upgrade;

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
    /// Reputation + trust signals — DNSBL, BIMI, DANE, DNSSEC, SPF-lookup-count, DKIM hygiene + Sender Score + Talos (v0.6).
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
        /// Skip Cisco Talos reputation lookup (default: on).
        #[arg(long)]
        no_talos: bool,
        /// Skip Sender Score lookups even if SENDERSCORE_API_KEY is set.
        #[arg(long)]
        no_senderscore: bool,
    },
    /// Leak + impersonation telemetry — HIBP, GitHub code search, lookalike domains (v0.4 + v0.6.1 --watch).
    Leak {
        #[arg(short, long)]
        domain: String,
        #[arg(short = 'f', long, default_value = "text")]
        format: String,
        /// Skip HIBP breach lookup.
        #[arg(long)]
        no_hibp: bool,
        /// Skip GitHub code search.
        #[arg(long)]
        no_github: bool,
        /// Skip lookalike domain enumeration + crt.sh checks.
        #[arg(long)]
        no_lookalikes: bool,
        /// crt.sh cert lookback window for lookalikes (days).
        #[arg(long, default_value_t = 90)]
        lookback_days: u32,
        /// Long-running mode: subscribe to certstream WS and emit JSON-line
        /// per cert issued for a lookalike variant. Ignores other --no-* flags.
        #[arg(long)]
        watch: bool,
        /// When --watch is set: exit after this many seconds. 0 = run forever.
        #[arg(long, default_value_t = 0)]
        watch_seconds: u64,
    },
    /// Start the embedded web UI (v0.5 — P4).
    Serve {
        /// Bind address — defaults to 127.0.0.1:7777 for local-only.
        #[arg(short, long, default_value = "127.0.0.1:7777")]
        bind: String,
    },
    /// Refresh local threat-intel caches (no binary change) (v0.5 — P4).
    Update,
    /// Self-update the cymail binary from the latest signed GitHub Release (v0.5 — P4).
    Upgrade {
        /// Print what would happen but don't actually swap the binary.
        #[arg(long)]
        dry_run: bool,
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
            let r = scan::scan_domain(&domain).await;
            output::print_report(&r, &format);
        }
        Commands::Bulk { file } => {
            print_banner();
            if let Ok(c) = std::fs::read_to_string(&file) {
                for d in c.lines().filter(|l| !l.trim().is_empty()) {
                    let r = scan::scan_domain(d.trim()).await;
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
        Commands::Reputation { domain, format, no_trust, dkim_selectors, no_talos, no_senderscore } => {
            print_banner();
            let mut opts = reputation::ReputationOpts::default();
            if no_trust { opts.include_trust = false; }
            opts.dkim_selectors.extend(dkim_selectors.into_iter().filter(|s| !s.trim().is_empty()));
            let mut r = reputation::run(&domain, &opts).await;

            // v0.6.0 — decorate with Sender Score + Talos.
            let mut ext_opts = reputation_ext::ExtOpts::default();
            if no_talos        { ext_opts.use_talos        = false; }
            if no_senderscore  { ext_opts.sender_score_key = None;  }
            r.extensions = Some(reputation_ext::decorate(&r, &ext_opts).await);

            print_reputation(&r, &format);
        }
        Commands::Leak { domain, format, no_hibp, no_github, no_lookalikes, lookback_days, watch, watch_seconds } => {
            print_banner();
            if watch {
                // Long-running CertStream watch mode (v0.6.1 — Sprint 98 P2).
                let mut wopts = ct_stream::WatchOpts::default();
                if watch_seconds > 0 {
                    wopts.max_runtime = Some(std::time::Duration::from_secs(watch_seconds));
                }
                let r = ct_stream::watch(&domain, &wopts, |hit| {
                    // Emit one JSON line per hit — pipeable to jq/SIEM.
                    println!("{}", serde_json::to_string(&hit).unwrap_or_default());
                }).await;
                if let Err(e) = r {
                    eprintln!("  watch error: {e}");
                    std::process::exit(1);
                }
                return;
            }

            let mut opts = leak::LeakOpts::default();
            if no_hibp        { opts.use_hibp       = false; }
            if no_github      { opts.use_github     = false; }
            if no_lookalikes  { opts.use_lookalikes = false; }
            opts.lookalike_lookback_days = lookback_days;
            let r = leak::run(&domain, &opts).await;
            print_leak(&r, &format);
        }
        Commands::Serve { bind } => {
            print_banner();
            let addr: std::net::SocketAddr = bind.parse().unwrap_or_else(|_| {
                eprintln!("  invalid --bind {bind}; defaulting to 127.0.0.1:7777");
                "127.0.0.1:7777".parse().unwrap()
            });
            if let Err(e) = server::serve(addr).await {
                eprintln!("  serve error: {e}");
            }
        }
        Commands::Update => {
            print_banner();
            match update::update() {
                Ok(r) => {
                    println!("  cache dir: {}", r.cache_dir.display());
                    println!("  refreshed: {}", r.feeds_refreshed.join(", "));
                    for s in &r.feeds_skipped { println!("  skipped:   {s}"); }
                    println!("  bytes written: {}", r.bytes_written);
                }
                Err(e) => eprintln!("  update failed: {e}"),
            }
        }
        Commands::Upgrade { dry_run } => {
            print_banner();
            let mut opts = upgrade::UpgradeOpts::default();
            opts.dry_run = dry_run;
            match upgrade::upgrade(&opts).await {
                Ok(msg) => println!("  {msg}"),
                Err(e)  => {
                    eprintln!("  upgrade: {e}");
                    std::process::exit(if matches!(e, upgrade::UpgradeError::AlreadyLatest) { 0 } else { 1 });
                }
            }
        }
        Commands::Version => {
            println!("cymail {} — Cybrium AI Email Scanner", env!("CARGO_PKG_VERSION"));
        }
    }
}


fn print_discovery(r: &discover::DiscoveryReport, format: &str) {
    match format {
        "json"  => { println!("{}", export::to_json(r)); return; }
        "sarif" => { println!("{}", export::discovery_to_sarif(r)); return; }
        "csv"   => { println!("{}", export::discovery_to_csv(r)); return; }
        "html"  => { println!("{}", export::discovery_to_html(r)); return; }
        _ => {}
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
    match format {
        "json"  => { println!("{}", export::to_json(r)); return; }
        "sarif" => { println!("{}", export::reputation_to_sarif(r)); return; }
        "csv"   => { println!("{}", export::reputation_to_csv(r)); return; }
        "html"  => { println!("{}", export::reputation_to_html(r)); return; }
        _ => {}
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

fn print_leak(r: &leak::LeakReport, format: &str) {
    match format {
        "json"  => { println!("{}", export::to_json(r)); return; }
        "sarif" => { println!("{}", export::leak_to_sarif(r)); return; }
        "csv"   => { println!("{}", export::leak_to_csv(r)); return; }
        "html"  => { println!("{}", export::leak_to_html(r)); return; }
        _ => {}
    }
    eprintln!("  \x1b[35m\x1b[1mLeak telemetry\x1b[0m  domain: \x1b[1m{}\x1b[0m  ({} ms)\n", r.domain, r.elapsed_ms);
    eprintln!("  Sources queried: {}", r.sources_queried.join(", "));

    eprintln!("\n  \x1b[1mBreaches (HIBP)\x1b[0m");
    if r.breaches.is_empty() {
        eprintln!("    \x1b[32mno domain-wide breaches recorded\x1b[0m");
    } else {
        for b in &r.breaches {
            let count = b.pwn_count.map(|n| format!("{n} accounts")).unwrap_or_default();
            eprintln!("    \x1b[31m✗\x1b[0m {} ({})  {} {}",
                b.title, b.breach_date.clone().unwrap_or_default(), count,
                if !b.data_classes.is_empty() {
                    format!("[{}]", b.data_classes.join(","))
                } else { String::new() }
            );
        }
    }

    eprintln!("\n  \x1b[1mGitHub code hits\x1b[0m");
    if r.github_leaks.is_empty() {
        eprintln!("    none");
    } else {
        for h in r.github_leaks.iter().take(10) {
            eprintln!("    {} — {}", h.repo, h.path);
            eprintln!("      \x1b[2m{}\x1b[0m", h.html_url);
        }
        if r.github_leaks.len() > 10 {
            eprintln!("    \x1b[2m… and {} more\x1b[0m", r.github_leaks.len() - 10);
        }
    }

    eprintln!("\n  \x1b[1mLookalike domains\x1b[0m");
    let issued: Vec<&leak::LookalikeHit> = r.lookalike_domains.iter().filter(|h| h.cert_issued).collect();
    if issued.is_empty() {
        eprintln!("    \x1b[32mno cert-bearing variants in lookback window\x1b[0m");
    } else {
        eprintln!("    \x1b[31m{} cert-bearing variants — somebody owns + provisioned these\x1b[0m", issued.len());
        for h in issued {
            eprintln!("    \x1b[31m✗\x1b[0m {:<32} ({:<14}) cert: {}",
                h.variant, h.variant_type, h.recent_cert_at.clone().unwrap_or_default());
        }
    }
    if !r.commercial_feeds.is_empty() {
        eprintln!("\n  \x1b[1mCommercial feeds\x1b[0m");
        for c in &r.commercial_feeds {
            eprintln!("    {}: {}", c.feed, c.result);
        }
    }
}
