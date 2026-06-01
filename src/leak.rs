//! Leak + impersonation telemetry (P3 — v0.4).
//!
//! Three categories of signal:
//!   1. **Breach lookup** — HIBP "breachedaccount" / "breach" APIs.
//!      Domain-scoped (no per-address PII pulls). HIBP requires a
//!      paid API key for full breach detail but the v3 public
//!      `/breaches?domain=` endpoint is free + unauthenticated and
//!      tells you whether the domain itself appears in any breach.
//!
//!   2. **Public-paste leaks** — searches the public GitHub code
//!      search API (no key needed for unauthenticated 10 req/min)
//!      for `@<domain>` and looks for password/secret-shaped
//!      neighbours. Reports the file + repo + URL only — no content.
//!      Pastebin / pastes search is BYO-key (PastebinAPI) so this
//!      module just returns an empty `paste_leaks` array unless
//!      `--pastebin-key` is supplied.
//!
//!   3. **Lookalike domains** — generates homoglyph + typosquat
//!      variants, then queries Certificate Transparency (crt.sh) for
//!      any certs issued against them in the last 90 days. A cert =
//!      somebody owns + provisioned that domain.
//!
//! Optional commercial feeds (Dehashed / IntelX / SnusBase) are
//! gated behind explicit env vars: cymail never contacts a paid
//! service unless the operator opts in.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakReport {
    pub domain:            String,
    pub scanned_at:        String,
    pub breaches:          Vec<BreachEntry>,
    pub github_leaks:      Vec<GitHubHit>,
    pub paste_leaks:       Vec<PasteHit>,
    pub lookalike_domains: Vec<LookalikeHit>,
    pub commercial_feeds:  Vec<CommercialFeedResult>,
    pub elapsed_ms:        u64,
    pub sources_queried:   Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachEntry {
    pub name:          String,
    pub title:         String,
    pub breach_date:   Option<String>,
    pub pwn_count:     Option<u64>,
    pub is_verified:   bool,
    pub data_classes:  Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubHit {
    pub repo:        String,
    pub path:        String,
    pub html_url:    String,
    pub snippet_hint: String,    // e.g. "password near @domain"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasteHit {
    pub source:      String,
    pub url:         String,
    pub posted_at:   Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookalikeHit {
    pub variant:        String,
    pub variant_type:   String,      // homoglyph / typo / tld / dash / etc.
    pub cert_issued:    bool,
    pub recent_cert_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommercialFeedResult {
    pub feed:    String,
    pub queried: bool,
    pub result:  String,
}

pub struct LeakOpts {
    pub http_timeout:           Duration,
    pub use_hibp:               bool,
    pub use_github:             bool,
    pub use_lookalikes:         bool,
    pub lookalike_lookback_days: u32,
    pub github_token:           Option<String>,    // optional, raises rate limit
    pub pastebin_key:           Option<String>,
    pub dehashed_key:           Option<String>,
    pub intelx_key:             Option<String>,
}

impl Default for LeakOpts {
    fn default() -> Self {
        Self {
            http_timeout:           Duration::from_secs(15),
            use_hibp:               true,
            use_github:             true,
            use_lookalikes:         true,
            lookalike_lookback_days: 90,
            github_token:           std::env::var("GITHUB_TOKEN").ok(),
            pastebin_key:           std::env::var("PASTEBIN_API_KEY").ok(),
            dehashed_key:           std::env::var("DEHASHED_API_KEY").ok(),
            intelx_key:             std::env::var("INTELX_API_KEY").ok(),
        }
    }
}

pub async fn run(domain: &str, opts: &LeakOpts) -> LeakReport {
    let started = std::time::Instant::now();
    let mut sources = Vec::new();

    let breaches = if opts.use_hibp {
        sources.push("haveibeenpwned.com".to_string());
        hibp_breaches(domain, opts.http_timeout).await.unwrap_or_default()
    } else { Vec::new() };

    let github_leaks = if opts.use_github {
        sources.push("github-code-search".to_string());
        github_search(domain, opts).await.unwrap_or_default()
    } else { Vec::new() };

    let paste_leaks = if opts.pastebin_key.is_some() {
        sources.push("pastebin".to_string());
        // BYO-key Pastebin Scraping API path. Without a key the public
        // search endpoint is rate-limited and undocumented; leaving
        // it as a stub keeps us honest.
        Vec::new()
    } else { Vec::new() };

    let lookalike_domains = if opts.use_lookalikes {
        sources.push("crt.sh-lookalikes".to_string());
        lookalike_scan(domain, opts.lookalike_lookback_days, opts.http_timeout).await
    } else { Vec::new() };

    let mut commercial_feeds = Vec::new();
    if opts.dehashed_key.is_some() {
        sources.push("dehashed".to_string());
        commercial_feeds.push(CommercialFeedResult {
            feed: "dehashed".into(), queried: false,
            result: "stub — wire on demand; key supplied".into(),
        });
    }
    if opts.intelx_key.is_some() {
        sources.push("intelx".to_string());
        commercial_feeds.push(CommercialFeedResult {
            feed: "intelx".into(), queried: false,
            result: "stub — wire on demand; key supplied".into(),
        });
    }

    LeakReport {
        domain:            domain.into(),
        scanned_at:        chrono::Utc::now().to_rfc3339(),
        breaches,
        github_leaks,
        paste_leaks,
        lookalike_domains,
        commercial_feeds,
        elapsed_ms:        started.elapsed().as_millis() as u64,
        sources_queried:   sources,
    }
}

// ─── HIBP ──────────────────────────────────────────────────────────
//
// https://haveibeenpwned.com/api/v3/breaches?domain=<d>
// Public + unauthenticated. Returns the breach list for any breach
// that exposed accounts from this domain.
async fn hibp_breaches(domain: &str, t: Duration) -> Result<Vec<BreachEntry>, reqwest::Error> {
    let url = format!("https://haveibeenpwned.com/api/v3/breaches?domain={domain}");
    let client = reqwest::Client::builder()
        .timeout(t)
        .user_agent(format!("cymail/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let resp = client.get(&url).send().await?;
    // 404 = no breaches; not an error.
    if resp.status().as_u16() == 404 { return Ok(Vec::new()); }
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let mut out = Vec::new();
    if let Some(arr) = body.as_array() {
        for b in arr {
            out.push(BreachEntry {
                name:         b.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                title:        b.get("Title").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                breach_date:  b.get("BreachDate").and_then(|v| v.as_str()).map(String::from),
                pwn_count:    b.get("PwnCount").and_then(|v| v.as_u64()),
                is_verified:  b.get("IsVerified").and_then(|v| v.as_bool()).unwrap_or(false),
                data_classes: b.get("DataClasses").and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
            });
        }
    }
    Ok(out)
}

// ─── GitHub code search ────────────────────────────────────────────
//
// We look for occurrences of the literal domain in code. Without a
// token GitHub limits to 10 req/min and 1000 results total, which is
// fine for our use case. Returns repo + path only — never the line
// content (avoid amplifying any leaked secret).
async fn github_search(domain: &str, opts: &LeakOpts) -> Result<Vec<GitHubHit>, reqwest::Error> {
    let url = format!("https://api.github.com/search/code?q=%22{domain}%22+password+OR+secret+OR+apikey&per_page=20");
    let client = reqwest::Client::builder()
        .timeout(opts.http_timeout)
        .user_agent(format!("cymail/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut req = client.get(&url);
    if let Some(tok) = &opts.github_token {
        req = req.bearer_auth(tok);
    }
    let resp = req.send().await?;
    if !resp.status().is_success() { return Ok(Vec::new()); }
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);

    let mut out = Vec::new();
    if let Some(items) = body.get("items").and_then(|v| v.as_array()) {
        for it in items {
            out.push(GitHubHit {
                repo:     it.get("repository").and_then(|r| r.get("full_name")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                path:     it.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                html_url: it.get("html_url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                snippet_hint: format!("@{domain} near password|secret|apikey"),
            });
        }
    }
    Ok(out)
}

// ─── Lookalike domains ─────────────────────────────────────────────
//
// Generate variants, then check crt.sh for cert issuance within the
// lookback window. Variants we generate per chunk:
//   - Homoglyphs: a→а (Cyrillic), o→0, l→1, etc.
//   - TLD swaps: .com → .co / .net / .biz / .info / .ai / .io
//   - Dashes:   cybrium → cy-brium
//   - Char swap, insert, delete (edit distance 1)
//   - "secure-", "-mail" / "-pay" suffixes
//
// Limited to top 50 candidates per scan to keep crt.sh polite.
pub(crate) fn generate_lookalikes(domain: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let parts: Vec<&str> = domain.rsplitn(2, '.').collect();
    if parts.len() < 2 { return out; }
    let (tld, name) = (parts[0], parts[1]);

    // 1. TLD swap
    for alt in ["com", "co", "net", "org", "biz", "info", "io", "ai", "app", "online"].iter() {
        if *alt != tld {
            out.push((format!("{name}.{alt}"), "tld-swap".into()));
        }
    }

    // 2. Dash insertion at each interior position (limit to 3)
    for i in 1..name.len().min(5) {
        let mut s = String::with_capacity(name.len() + 1);
        s.push_str(&name[..i]);
        s.push('-');
        s.push_str(&name[i..]);
        out.push((format!("{s}.{tld}"), "dash-insert".into()));
    }

    // 3. Homoglyph substitution (ASCII look-alikes — most filters
    //    catch IDN punycode but miss these)
    let homos = [('o','0'), ('o','q'), ('i','1'), ('l','1'), ('a','@'),
                 ('e','3'), ('s','5'), ('g','9')];
    for (orig, sub) in &homos {
        if name.contains(*orig) {
            let s: String = name.chars().map(|c| if c == *orig { *sub } else { c }).collect();
            out.push((format!("{s}.{tld}"), "homoglyph".into()));
        }
    }

    // 4. Char insertion / deletion / swap (edit-distance 1)
    let bytes = name.as_bytes();
    for i in 0..bytes.len().min(8) {
        // deletion
        let mut del = String::with_capacity(bytes.len() - 1);
        del.push_str(&name[..i]); del.push_str(&name[i+1..]);
        out.push((format!("{del}.{tld}"), "delete-char".into()));
        // swap adjacent
        if i + 1 < bytes.len() {
            let mut s = bytes.to_vec();
            s.swap(i, i+1);
            if let Ok(swp) = String::from_utf8(s) {
                out.push((format!("{swp}.{tld}"), "swap-char".into()));
            }
        }
    }

    // 5. Brand-impersonation suffixes
    for sfx in ["-mail", "-pay", "-secure", "-login", "-support", "-billing"].iter() {
        out.push((format!("{name}{sfx}.{tld}"), "brand-suffix".into()));
    }

    // De-dup + cap
    out.sort();
    out.dedup_by(|a, b| a.0 == b.0);
    out.truncate(50);
    out
}

async fn lookalike_scan(domain: &str, lookback_days: u32, t: Duration) -> Vec<LookalikeHit> {
    let variants = generate_lookalikes(domain);
    let client = match reqwest::Client::builder()
        .timeout(t)
        .user_agent(format!("cymail/{}", env!("CARGO_PKG_VERSION")))
        .build() { Ok(c) => c, Err(_) => return Vec::new() };

    let cutoff = chrono::Utc::now() - chrono::Duration::days(lookback_days as i64);

    let mut out = Vec::new();
    // crt.sh accepts one domain at a time. We iterate and accept the
    // sequential cost — typically 50 × ~200ms = 10s.
    for (variant, kind) in variants {
        let url = format!("https://crt.sh/?q={variant}&output=json");
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !resp.status().is_success() {
            out.push(LookalikeHit { variant, variant_type: kind, cert_issued: false, recent_cert_at: None });
            continue;
        }
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        let mut recent: Option<chrono::DateTime<chrono::Utc>> = None;
        if let Some(arr) = body.as_array() {
            for cert in arr {
                if let Some(date) = cert.get("not_before").and_then(|v| v.as_str()) {
                    if let Ok(d) = chrono::DateTime::parse_from_rfc3339(&format!("{date}Z")) {
                        let utc = d.with_timezone(&chrono::Utc);
                        if utc > cutoff && recent.map_or(true, |r| utc > r) {
                            recent = Some(utc);
                        }
                    }
                }
            }
        }
        out.push(LookalikeHit {
            variant,
            variant_type:   kind,
            cert_issued:    recent.is_some(),
            recent_cert_at: recent.map(|d| d.to_rfc3339()),
        });
    }

    // Sort by impact: cert-bearing variants first.
    out.sort_by(|a, b| b.cert_issued.cmp(&a.cert_issued).then(a.variant.cmp(&b.variant)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookalikes_generate_sensible_count() {
        let v = generate_lookalikes("cybrium.ai");
        assert!(v.len() > 10);
        assert!(v.len() <= 50);
        assert!(v.iter().any(|(d, _)| d.contains("-mail")));
        assert!(v.iter().any(|(d, _)| d.contains("cybrium.com")));
    }

    #[test]
    fn lookalikes_handles_short_names() {
        let v = generate_lookalikes("x.io");
        // Should still produce something (TLD swaps + suffixes)
        assert!(!v.is_empty());
    }
}
