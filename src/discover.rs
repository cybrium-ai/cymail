//! Email discovery (P1 — theHarvester parity, with safer SMTP probes).
//!
//! Sources, in order of cost:
//!   1. crt.sh — Certificate Transparency SANs. Free, no auth.
//!   2. DNS SOA RNAME — the responsible-party email baked into SOA.
//!   3. Pattern guessing — first.last / f.last / firstlast / etc.
//!      Validated with SMTP RCPT TO against the domain's MX hosts.
//!   4. EmailRep.io reputation — free tier, no key. Per-address.
//!   5. Catch-all detection — probe a random non-existent address.
//!      If accepted, every guess is "valid" so we suppress them.
//!
//! Schema stays *separate* from `EmailReport` (the `scan` subcommand's
//! output). Platform's `cymail_runner.py` only parses `scan` output —
//! `discover` is a brand-new surface, so it can't break the existing
//! integration.

use std::collections::HashSet;
use std::time::Duration;

use hickory_resolver::Resolver;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// One discovered email + everything we know about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEmail {
    pub address:    String,
    pub source:     String,            // crt.sh / dns-soa / pattern / etc.
    pub validated:  Option<bool>,      // Some(true) = MX RCPT TO accepted
    pub reputation: Option<Reputation>,
}

/// EmailRep.io-shaped reputation snapshot. Fields kept minimal and
/// stable so they survive the free→paid tier shift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reputation {
    pub source:     String,
    pub score:      Option<i32>,       // 0–100 if provider returns one
    pub suspicious: Option<bool>,
    pub references: Option<i32>,
    pub blacklisted: Option<bool>,
    pub malicious:   Option<bool>,
    pub credentials_leaked: Option<bool>,
    pub data_breach:        Option<bool>,
    pub raw: Option<serde_json::Value>,
}

/// Top-level discover report — emitted as JSON when --format=json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryReport {
    pub domain:           String,
    pub scanned_at:       String,
    pub mx_hosts:         Vec<String>,
    pub catch_all:        Option<bool>,
    pub emails:           Vec<DiscoveredEmail>,
    pub sources_queried:  Vec<String>,
    pub elapsed_ms:       u64,
}

/// One-shot orchestrator. `opts` tunes which sources to run; pattern
/// validation + catch-all probes are skipped when `--no-smtp`.
pub struct DiscoverOpts {
    pub use_crtsh:        bool,
    pub use_dns_soa:      bool,
    pub use_patterns:     bool,
    pub use_reputation:   bool,
    pub use_smtp_validate: bool,
    pub seed_names:       Vec<String>,   // patterns to guess from
    pub http_timeout:     Duration,
    pub smtp_timeout:     Duration,
}

impl Default for DiscoverOpts {
    fn default() -> Self {
        Self {
            use_crtsh:         true,
            use_dns_soa:       true,
            use_patterns:      true,
            use_reputation:    true,
            use_smtp_validate: true,
            // Default seed list — short, well-known. Operators can
            // pass --seed name1,name2 to supplement.
            seed_names: vec![
                "admin".into(), "info".into(), "contact".into(), "hello".into(),
                "support".into(), "sales".into(), "security".into(), "abuse".into(),
                "postmaster".into(), "webmaster".into(), "noreply".into(), "no-reply".into(),
                "press".into(), "legal".into(), "privacy".into(), "billing".into(),
            ],
            http_timeout: Duration::from_secs(10),
            smtp_timeout: Duration::from_secs(8),
        }
    }
}

pub async fn run(domain: &str, opts: &DiscoverOpts) -> DiscoveryReport {
    let started = std::time::Instant::now();
    let mut emails: Vec<DiscoveredEmail> = Vec::new();
    let mut seen:   HashSet<String>      = HashSet::new();
    let mut sources_queried = Vec::new();

    let mx_hosts = resolve_mx(domain).await;

    // 1. crt.sh — SAN emails on certs issued for this domain
    if opts.use_crtsh {
        sources_queried.push("crt.sh".to_string());
        if let Ok(hits) = crtsh_emails(domain, opts.http_timeout).await {
            for addr in hits {
                if seen.insert(addr.to_lowercase()) {
                    emails.push(DiscoveredEmail {
                        address: addr, source: "crt.sh".into(),
                        validated: None, reputation: None,
                    });
                }
            }
        }
    }

    // 2. DNS SOA RNAME
    if opts.use_dns_soa {
        sources_queried.push("dns-soa".to_string());
        if let Some(addr) = dns_soa_email(domain).await {
            if seen.insert(addr.to_lowercase()) {
                emails.push(DiscoveredEmail {
                    address: addr, source: "dns-soa".into(),
                    validated: None, reputation: None,
                });
            }
        }
    }

    // 3. Pattern guessing (seed-name @ domain). Always cheap to add;
    //    SMTP validation gates the noise.
    if opts.use_patterns {
        sources_queried.push("pattern".to_string());
        for name in &opts.seed_names {
            let addr = format!("{name}@{domain}");
            if seen.insert(addr.to_lowercase()) {
                emails.push(DiscoveredEmail {
                    address: addr, source: "pattern".into(),
                    validated: None, reputation: None,
                });
            }
        }
    }

    // 4. Catch-all probe — once, against the first MX. Validation
    //    results are meaningless when catch_all=true (server accepts
    //    every RCPT), so we record the bit and skip SMTP validation.
    let catch_all = if opts.use_smtp_validate && !mx_hosts.is_empty() {
        sources_queried.push("smtp-catchall-probe".to_string());
        Some(probe_catch_all(&mx_hosts[0], domain, opts.smtp_timeout).await)
    } else {
        None
    };

    // 5. SMTP RCPT TO validation for pattern guesses (only when NOT
    //    catch-all). crt.sh / dns-soa addresses are not validated —
    //    they're already confirmed by their source.
    if opts.use_smtp_validate && catch_all == Some(false) && !mx_hosts.is_empty() {
        sources_queried.push("smtp-validate".to_string());
        for em in emails.iter_mut().filter(|e| e.source == "pattern") {
            em.validated = Some(
                rcpt_to(&mx_hosts[0], &em.address, opts.smtp_timeout).await
            );
        }
    }

    // 6. Reputation lookup for every validated or sourced email.
    //    Free EmailRep.io tier — 1 req/s soft limit, no key needed.
    if opts.use_reputation {
        sources_queried.push("emailrep.io".to_string());
        for em in emails.iter_mut() {
            // Only lookup confirmed (validated or sourced) addresses
            // to keep the request count low.
            let confirmed = em.source != "pattern" || em.validated == Some(true);
            if !confirmed { continue; }
            em.reputation = emailrep_lookup(&em.address, opts.http_timeout).await.ok();
        }
    }

    DiscoveryReport {
        domain:           domain.into(),
        scanned_at:       chrono::Utc::now().to_rfc3339(),
        mx_hosts,
        catch_all,
        emails,
        sources_queried,
        elapsed_ms:       started.elapsed().as_millis() as u64,
    }
}

// ─────────────────────────────────────────────────────────────────────
// crt.sh — Certificate Transparency. SAN entries that look like emails
// (`rfc822Name`) get extracted. Free API, JSON output.
// ─────────────────────────────────────────────────────────────────────
async fn crtsh_emails(domain: &str, t: Duration) -> Result<Vec<String>, reqwest::Error> {
    let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
    let client = reqwest::Client::builder()
        .timeout(t)
        .user_agent(format!("cymail/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let body: serde_json::Value = client.get(&url).send().await?.json().await?;
    let mut out = Vec::new();
    if let Some(arr) = body.as_array() {
        for entry in arr {
            // crt.sh returns `name_value` with newline-separated SANs.
            // Some are email addresses (mostly older S/MIME certs),
            // most are DNS names. Extract anything containing "@".
            if let Some(v) = entry.get("name_value").and_then(|v| v.as_str()) {
                for line in v.split('\n') {
                    let trim = line.trim().trim_matches('*').trim_matches('.');
                    if trim.contains('@') && trim.ends_with(domain) {
                        out.push(trim.to_string());
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────
// DNS SOA RNAME — the second word of the SOA record, with the first
// `.` translated to `@`. "ns1.example.com hostmaster.example.com 2024"
// → "hostmaster@example.com". Often the only "real" contact on a
// neglected domain.
// ─────────────────────────────────────────────────────────────────────
async fn dns_soa_email(domain: &str) -> Option<String> {
    let resolver = Resolver::builder_tokio().ok()?.build();
    let resp = resolver.soa_lookup(domain).await.ok()?;
    let soa = resp.iter().next()?;
    let rname = soa.rname().to_string();
    // hostmaster.example.com. → hostmaster@example.com
    let trimmed = rname.trim_end_matches('.');
    let (local, dom) = trimmed.split_once('.')?;
    Some(format!("{local}@{dom}"))
}

// ─────────────────────────────────────────────────────────────────────
// MX resolution — sorted by priority. Caller picks the lowest-pref MX
// for SMTP probes.
// ─────────────────────────────────────────────────────────────────────
async fn resolve_mx(domain: &str) -> Vec<String> {
    let Ok(builder) = Resolver::builder_tokio() else { return Vec::new(); };
    let resolver = builder.build();
    let mut mxs: Vec<(u16, String)> = Vec::new();
    if let Ok(resp) = resolver.mx_lookup(domain).await {
        for r in resp.iter() {
            mxs.push((r.preference(), r.exchange().to_string().trim_end_matches('.').to_string()));
        }
    }
    mxs.sort_by_key(|(p, _)| *p);
    mxs.into_iter().map(|(_, h)| h).collect()
}

// ─────────────────────────────────────────────────────────────────────
// SMTP catch-all probe. Connects to MX:25, EHLO + MAIL FROM + RCPT TO
// to a long random local-part. If the server says 250 (accepted), the
// domain accepts every recipient → catch_all=true.
// ─────────────────────────────────────────────────────────────────────
async fn probe_catch_all(mx: &str, domain: &str, t: Duration) -> bool {
    use rand::Rng;
    let nonce: String = (0..24)
        .map(|_| {
            let c = rand::thread_rng().gen_range(b'a'..=b'z');
            c as char
        })
        .collect();
    let addr = format!("definitely-{nonce}@{domain}");
    rcpt_to(mx, &addr, t).await
}

// ─────────────────────────────────────────────────────────────────────
// SMTP RCPT TO validation. Returns true on a 250 response. Falls back
// to false on network errors / 550 / 553 / 421 to keep the result
// strictly "validated".
//
// Sends a clean QUIT after the RCPT so we don't leave the server
// holding state. Never actually sends DATA — the RCPT TO is enough to
// learn whether the address exists.
// ─────────────────────────────────────────────────────────────────────
async fn rcpt_to(mx: &str, address: &str, t: Duration) -> bool {
    let f = async {
        let mut stream = TcpStream::connect((mx, 25u16)).await.ok()?;
        let (r, mut w) = stream.split();
        let mut reader = BufReader::new(r);
        let mut line = String::new();

        // Greeting
        reader.read_line(&mut line).await.ok()?;
        if !line.starts_with("220") { return None; }
        line.clear();

        w.write_all(format!("EHLO cymail.cybrium.ai\r\n").as_bytes()).await.ok()?;
        // Drain EHLO multi-line response
        loop {
            reader.read_line(&mut line).await.ok()?;
            // multi-line responses use "250-..." then final "250 ..."
            if line.starts_with("250 ") { break; }
            if !line.starts_with("250-") { return None; }
            line.clear();
        }
        line.clear();

        w.write_all(b"MAIL FROM:<probe@cymail.cybrium.ai>\r\n").await.ok()?;
        reader.read_line(&mut line).await.ok()?;
        if !line.starts_with("250") { return None; }
        line.clear();

        w.write_all(format!("RCPT TO:<{address}>\r\n").as_bytes()).await.ok()?;
        reader.read_line(&mut line).await.ok()?;
        let accepted = line.starts_with("250");

        // Clean up — server stays happy.
        let _ = w.write_all(b"QUIT\r\n").await;

        Some(accepted)
    };
    timeout(t, f).await.ok().flatten().unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────────────
// EmailRep.io free tier (https://emailrep.io/<email>). 1 req/s soft
// rate limit. Returns a minimal reputation snapshot.
// ─────────────────────────────────────────────────────────────────────
async fn emailrep_lookup(email: &str, t: Duration) -> Result<Reputation, reqwest::Error> {
    let url = format!("https://emailrep.io/{}", urlencoding_minimal(email));
    let client = reqwest::Client::builder()
        .timeout(t)
        .user_agent(format!("cymail/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let body: serde_json::Value = client.get(&url).send().await?.json().await?;
    let details = body.get("details").cloned().unwrap_or(serde_json::Value::Null);

    Ok(Reputation {
        source:             "emailrep.io".into(),
        score:              body.get("reputation").and_then(|v| v.as_str()).map(grade_to_score),
        suspicious:         body.get("suspicious").and_then(|v| v.as_bool()),
        references:         body.get("references").and_then(|v| v.as_i64()).map(|n| n as i32),
        blacklisted:        details.get("blacklisted").and_then(|v| v.as_bool()),
        malicious:          details.get("malicious_activity").and_then(|v| v.as_bool()),
        credentials_leaked: details.get("credentials_leaked").and_then(|v| v.as_bool()),
        data_breach:        details.get("data_breach").and_then(|v| v.as_bool()),
        raw:                Some(body),
    })
}

fn grade_to_score(grade: &str) -> i32 {
    match grade {
        "high"   => 90,
        "medium" => 60,
        "low"    => 30,
        "none"   => 10,
        _        => 50,
    }
}

// Tiny urlencoder — avoids pulling in the `urlencoding` crate just for
// this one call. Email-local-part safe (covers + . _ - @).
fn urlencoding_minimal(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
            b'-' | b'_' | b'.' | b'~' | b'@' | b'+' => (b as char).to_string(),
            _ => format!("%{:02X}", b),
        })
        .collect()
}
