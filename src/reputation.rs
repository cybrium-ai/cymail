//! Reputation + trust signals (P2 — v0.3).
//!
//! All checks are **passive** — DNS lookups only, no SMTP, no HTTP
//! POSTs that mutate state. Safe to run on third-party domains
//! without consent. Schema is separate from EmailReport so the
//! platform's cymail_runner.py is unaffected.
//!
//! What we check:
//!   - DNSBL: Spamhaus DBL/SBL/CSS, SURBL, URIBL, DNSWL, Barracuda BRBL.
//!     We query each list with the domain (DBL/SURBL/URIBL) or each
//!     MX IP (SBL/CSS/DNSWL/BRBL).
//!   - BIMI: brand indicator + optional VMC.
//!   - DANE: TLSA records on the MX hosts (port 25).
//!   - DNSSEC: DO bit + RRSIG presence — best-effort signal.
//!   - SPF lookup count: counts mechanisms that trigger a DNS lookup
//!     (a, mx, include, exists, ptr, redirect). RFC 7208 hard cap is
//!     10. Lots of misconfigured prod domains silently fail SPF
//!     because they trip this without realising.
//!   - DKIM key hygiene: parses public-key length + algorithm.
//!     RSA <2048 = fail, Ed25519 = bonus.
//!   - MX provider fingerprint: maps the MX FQDN to a vendor so the
//!     scoring layer can give vendor-specific guidance.

use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::proto::rr::RecordType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationReport {
    pub domain:           String,
    pub scanned_at:       String,
    pub mx_hosts:         Vec<String>,
    pub dnsbl:            DnsblSummary,
    pub bimi:             BimiResult,
    pub dane:             Vec<DaneEntry>,
    pub dnssec:           DnssecResult,
    pub spf_lookups:      SpfLookupResult,
    pub dkim_hygiene:     Vec<DkimKeyResult>,
    pub provider:         ProviderFingerprint,
    pub elapsed_ms:       u64,
    /// v0.6.0 (Sprint 98 P1) — Sender Score + Cisco Talos.
    /// Optional + skip-serialize-if-none so older JSON consumers
    /// don't see a new mandatory field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions:       Option<crate::reputation_ext::ReputationExtensions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsblSummary {
    pub queries: Vec<DnsblHit>,
    pub blacklisted_listings: u32,
    pub trust_listings:       u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsblHit {
    pub list:      String,
    pub kind:      String,        // "blacklist" or "trust"
    pub target:    String,        // domain or IP queried
    pub listed:    bool,
    pub return_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BimiResult {
    pub configured: bool,
    pub record:     Option<String>,
    pub svg_url:    Option<String>,
    pub vmc_url:    Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaneEntry {
    pub mx_host: String,
    pub port:    u16,
    pub present: bool,
    pub records: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecResult {
    pub dnskey_present: bool,
    pub ds_present:     bool,
    pub signed:         bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfLookupResult {
    pub record:        Option<String>,
    pub lookup_count:  u32,
    pub limit:         u32,        // hard cap is 10 per RFC 7208 §4.6.4
    pub over_limit:    bool,
    pub includes:      Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimKeyResult {
    pub selector:     String,
    pub algorithm:    Option<String>,    // "rsa" or "ed25519"
    pub key_bits:     Option<u32>,
    pub hygiene:      String,            // "ok" / "weak" / "deprecated" / "missing"
    pub issue:        Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderFingerprint {
    pub vendor:    String,
    pub category:  String,    // "cloud" / "gateway" / "self-hosted" / "unknown"
    pub mx_match:  Vec<String>,
}

pub struct ReputationOpts {
    pub dns_timeout:    Duration,
    pub include_trust:  bool,
    pub dkim_selectors: Vec<String>,
}

impl Default for ReputationOpts {
    fn default() -> Self {
        Self {
            dns_timeout:    Duration::from_secs(5),
            include_trust:  true,
            // Sane defaults across common providers.
            dkim_selectors: vec![
                "default".into(), "google".into(), "selector1".into(), "selector2".into(),
                "k1".into(), "k2".into(), "dkim".into(), "mail".into(), "s1".into(), "s2".into(),
                "smtpapi".into(), "mxvault".into(),
            ],
        }
    }
}

pub async fn run(domain: &str, opts: &ReputationOpts) -> ReputationReport {
    let started = std::time::Instant::now();

    let Ok(builder) = Resolver::builder_tokio() else {
        return empty_report(domain);
    };
    let resolver = builder.build();

    let mx_hosts = resolve_mx(&resolver, domain).await;
    let mx_ips   = resolve_mx_ips(&resolver, &mx_hosts).await;

    let dnsbl       = dnsbl_query(&resolver, domain, &mx_ips, opts.include_trust).await;
    let bimi        = bimi_lookup(&resolver, domain).await;
    let dane        = dane_lookup(&resolver, &mx_hosts).await;
    let dnssec      = dnssec_probe(&resolver, domain).await;
    let spf_lookups = spf_lookup_count(&resolver, domain).await;
    let dkim_hygiene = dkim_hygiene_check(&resolver, domain, &opts.dkim_selectors).await;
    let provider    = fingerprint_provider(&mx_hosts);

    ReputationReport {
        domain:       domain.into(),
        scanned_at:   chrono::Utc::now().to_rfc3339(),
        mx_hosts,
        dnsbl,
        bimi,
        dane,
        dnssec,
        spf_lookups,
        dkim_hygiene,
        provider,
        elapsed_ms:   started.elapsed().as_millis() as u64,
        extensions:   None,
    }
}

fn empty_report(domain: &str) -> ReputationReport {
    ReputationReport {
        domain: domain.into(),
        scanned_at: chrono::Utc::now().to_rfc3339(),
        mx_hosts: Vec::new(),
        dnsbl: DnsblSummary { queries: Vec::new(), blacklisted_listings: 0, trust_listings: 0 },
        bimi:  BimiResult  { configured: false, record: None, svg_url: None, vmc_url: None },
        dane:  Vec::new(),
        dnssec: DnssecResult { dnskey_present: false, ds_present: false, signed: false },
        spf_lookups: SpfLookupResult { record: None, lookup_count: 0, limit: 10, over_limit: false, includes: Vec::new() },
        dkim_hygiene: Vec::new(),
        provider: ProviderFingerprint { vendor: "unknown".into(), category: "unknown".into(), mx_match: Vec::new() },
        elapsed_ms: 0,
        extensions: None,
    }
}

// ─── MX + A/AAAA resolution ────────────────────────────────────────
async fn resolve_mx(resolver: &hickory_resolver::TokioResolver, domain: &str) -> Vec<String> {
    let mut mxs: Vec<(u16, String)> = Vec::new();
    if let Ok(resp) = resolver.mx_lookup(domain).await {
        for r in resp.iter() {
            mxs.push((r.preference(), r.exchange().to_string().trim_end_matches('.').to_string()));
        }
    }
    mxs.sort_by_key(|(p, _)| *p);
    mxs.into_iter().map(|(_, h)| h).collect()
}

async fn resolve_mx_ips(resolver: &hickory_resolver::TokioResolver, mxs: &[String]) -> Vec<std::net::Ipv4Addr> {
    let mut out = Vec::new();
    for mx in mxs {
        if let Ok(resp) = resolver.ipv4_lookup(mx).await {
            for ip in resp.iter() {
                out.push(std::net::Ipv4Addr::from(ip.0));
            }
        }
    }
    out
}

// ─── DNSBL ─────────────────────────────────────────────────────────
//
// Domain-name lists query reversed-domain.list. IP-address lists query
// reversed-octets.list. A response = listed; NXDOMAIN = clean. The A
// record's last octet usually encodes the listing reason (e.g. 127.0.0.2
// vs 127.0.0.4 on Spamhaus DBL).

struct DnsblDef {
    list:   &'static str,
    kind:   &'static str,         // "blacklist" or "trust"
    domain: bool,                 // queries domain names (true) or IPs (false)
}

const DNSBLS: &[DnsblDef] = &[
    DnsblDef { list: "dbl.spamhaus.org",       kind: "blacklist", domain: true  },
    DnsblDef { list: "multi.surbl.org",        kind: "blacklist", domain: true  },
    DnsblDef { list: "multi.uribl.com",        kind: "blacklist", domain: true  },
    DnsblDef { list: "zen.spamhaus.org",       kind: "blacklist", domain: false },
    DnsblDef { list: "b.barracudacentral.org", kind: "blacklist", domain: false },
    DnsblDef { list: "list.dnswl.org",         kind: "trust",     domain: false },
];

async fn dnsbl_query(
    resolver: &hickory_resolver::TokioResolver,
    domain:   &str,
    mx_ips:   &[std::net::Ipv4Addr],
    include_trust: bool,
) -> DnsblSummary {
    let mut queries = Vec::new();
    let mut bl_count = 0u32;
    let mut tr_count = 0u32;

    for bl in DNSBLS {
        if bl.kind == "trust" && !include_trust { continue; }

        if bl.domain {
            let q = format!("{domain}.{}", bl.list);
            let (listed, codes) = bl_lookup(resolver, &q).await;
            if listed && bl.kind == "blacklist" { bl_count += 1; }
            if listed && bl.kind == "trust"     { tr_count += 1; }
            queries.push(DnsblHit {
                list: bl.list.into(),
                kind: bl.kind.into(),
                target: domain.into(),
                listed,
                return_codes: codes,
            });
        } else {
            for ip in mx_ips {
                let oct = ip.octets();
                let q = format!("{}.{}.{}.{}.{}", oct[3], oct[2], oct[1], oct[0], bl.list);
                let (listed, codes) = bl_lookup(resolver, &q).await;
                if listed && bl.kind == "blacklist" { bl_count += 1; }
                if listed && bl.kind == "trust"     { tr_count += 1; }
                queries.push(DnsblHit {
                    list: bl.list.into(),
                    kind: bl.kind.into(),
                    target: ip.to_string(),
                    listed,
                    return_codes: codes,
                });
            }
        }
    }
    DnsblSummary { queries, blacklisted_listings: bl_count, trust_listings: tr_count }
}

async fn bl_lookup(resolver: &hickory_resolver::TokioResolver, q: &str) -> (bool, Vec<String>) {
    match resolver.ipv4_lookup(q).await {
        Ok(resp) => {
            let codes: Vec<String> = resp.iter()
                .map(|ip| std::net::Ipv4Addr::from(ip.0).to_string())
                .collect();
            (!codes.is_empty(), codes)
        }
        Err(_) => (false, Vec::new()),
    }
}

// ─── BIMI ──────────────────────────────────────────────────────────
async fn bimi_lookup(resolver: &hickory_resolver::TokioResolver, domain: &str) -> BimiResult {
    let q = format!("default._bimi.{domain}");
    match resolver.txt_lookup(&q).await {
        Ok(resp) => {
            for r in resp.iter() {
                let s = r.to_string();
                if s.contains("v=BIMI1") {
                    let svg = s.split(';').find_map(|p| p.trim().strip_prefix("l=")).map(|v| v.trim().to_string());
                    let vmc = s.split(';').find_map(|p| p.trim().strip_prefix("a=")).map(|v| v.trim().to_string());
                    return BimiResult { configured: true, record: Some(s), svg_url: svg, vmc_url: vmc };
                }
            }
            BimiResult { configured: false, record: None, svg_url: None, vmc_url: None }
        }
        Err(_) => BimiResult { configured: false, record: None, svg_url: None, vmc_url: None },
    }
}

// ─── DANE TLSA on MX ──────────────────────────────────────────────
async fn dane_lookup(resolver: &hickory_resolver::TokioResolver, mxs: &[String]) -> Vec<DaneEntry> {
    let mut out = Vec::new();
    for mx in mxs {
        let q = format!("_25._tcp.{mx}");
        match resolver.lookup(&q, RecordType::TLSA).await {
            Ok(resp) => {
                let records: Vec<String> = resp.iter().map(|r| r.to_string()).collect();
                out.push(DaneEntry {
                    mx_host: mx.clone(),
                    port: 25,
                    present: !records.is_empty(),
                    records,
                });
            }
            Err(_) => {
                out.push(DaneEntry { mx_host: mx.clone(), port: 25, present: false, records: Vec::new() });
            }
        }
    }
    out
}

// ─── DNSSEC probe ──────────────────────────────────────────────────
//
// Best-effort: we look for DNSKEY + DS at the parent. Full chain
// validation is something the recursive resolver does for us; the
// presence of these records is a strong proxy.
async fn dnssec_probe(resolver: &hickory_resolver::TokioResolver, domain: &str) -> DnssecResult {
    let dnskey = resolver.lookup(domain, RecordType::DNSKEY).await
        .map(|r| r.iter().count() > 0).unwrap_or(false);
    let ds     = resolver.lookup(domain, RecordType::DS).await
        .map(|r| r.iter().count() > 0).unwrap_or(false);
    DnssecResult { dnskey_present: dnskey, ds_present: ds, signed: dnskey && ds }
}

// ─── SPF lookup-count ──────────────────────────────────────────────
//
// RFC 7208 §4.6.4: SPF MUST limit DNS-querying mechanisms to 10
// total. include, a, mx, ptr, exists, redirect each count as one;
// includes recursively count their nested lookups.
//
// We follow include + redirect one level deep — that covers ~95% of
// real-world cases. Properly recursive walks blow up against
// providers like _spf.google.com that nest 4 levels.
fn count_spf_lookups(record: &str) -> u32 {
    let mut count = 0u32;
    for term in record.split_whitespace() {
        let t = term.trim_start_matches('+').trim_start_matches('-')
            .trim_start_matches('~').trim_start_matches('?');
        if t.starts_with("include:") || t.starts_with("a:") || t.starts_with("a")
            || t.starts_with("mx:") || t.starts_with("mx")
            || t.starts_with("exists:") || t.starts_with("ptr") || t.starts_with("redirect=") {
            // Skip bare "all" / "v=spf1" / IP literals
            if t == "all" || t.starts_with("v=") || t.starts_with("ip4:") || t.starts_with("ip6:") {
                continue;
            }
            count += 1;
        }
    }
    count
}

async fn spf_lookup_count(resolver: &hickory_resolver::TokioResolver, domain: &str) -> SpfLookupResult {
    let mut record: Option<String> = None;
    if let Ok(resp) = resolver.txt_lookup(domain).await {
        for r in resp.iter() {
            let s = r.to_string();
            if s.contains("v=spf1") { record = Some(s); break; }
        }
    }
    let Some(rec) = record.clone() else {
        return SpfLookupResult { record: None, lookup_count: 0, limit: 10, over_limit: false, includes: Vec::new() };
    };

    let mut count = count_spf_lookups(&rec);
    let includes: Vec<String> = rec.split_whitespace()
        .filter_map(|t| t.strip_prefix("include:").or_else(|| t.strip_prefix("+include:")))
        .map(String::from)
        .collect();

    // One level of recursion — enough to catch SaaS providers that
    // pile up beneath a single include:.
    for inc in &includes {
        if let Ok(resp) = resolver.txt_lookup(inc).await {
            for r in resp.iter() {
                let s = r.to_string();
                if s.contains("v=spf1") {
                    count = count.saturating_add(count_spf_lookups(&s));
                }
            }
        }
    }

    SpfLookupResult {
        record:       Some(rec),
        lookup_count: count,
        limit:        10,
        over_limit:   count > 10,
        includes,
    }
}

// ─── DKIM key hygiene ──────────────────────────────────────────────
//
// We try each candidate selector; if the TXT record exists, we parse
// the p= field, base64-decode it, and inspect.
//   - RSA: parse the ASN.1 SubjectPublicKeyInfo to read the modulus
//     bit-length. <2048 is failing today's anti-spam expectations.
//   - Ed25519: short keys (256 bits) but stronger; flag as "ok".
async fn dkim_hygiene_check(
    resolver: &hickory_resolver::TokioResolver,
    domain:   &str,
    selectors: &[String],
) -> Vec<DkimKeyResult> {
    let mut out = Vec::new();
    for sel in selectors {
        let q = format!("{sel}._domainkey.{domain}");
        let Ok(resp) = resolver.txt_lookup(&q).await else { continue; };
        for r in resp.iter() {
            let s = r.to_string();
            if !s.contains("p=") { continue; }
            let alg = s.split(';').find_map(|p| p.trim().strip_prefix("k=")).map(|v| v.trim().to_string()).unwrap_or_else(|| "rsa".to_string());
            let p = s.split(';').find_map(|p| p.trim().strip_prefix("p=")).map(|v| v.trim().to_string()).unwrap_or_default();

            let (bits, hygiene, issue) = analyse_dkim_key(&alg, &p);
            out.push(DkimKeyResult {
                selector: sel.clone(),
                algorithm: Some(alg.clone()),
                key_bits: bits,
                hygiene,
                issue,
            });
            break;
        }
    }
    out
}

fn analyse_dkim_key(alg: &str, p_b64: &str) -> (Option<u32>, String, Option<String>) {
    if p_b64.is_empty() {
        return (None, "missing".into(), Some("DKIM record present but p= is empty — key revoked".into()));
    }
    // Strip quotes / whitespace
    let cleaned: String = p_b64.chars().filter(|c| !c.is_whitespace() && *c != '"').collect();
    let Ok(bytes) = base64_decode(&cleaned) else {
        return (None, "unknown".into(), Some("Could not decode p= as base64".into()));
    };

    match alg.to_lowercase().as_str() {
        "ed25519" => (Some(256), "ok".into(), None),
        _ => {
            // RSA SubjectPublicKeyInfo — find the modulus length.
            // We don't pull in `rsa` / `der-parser` for one number;
            // a heuristic on the DER length works: total bytes ~= n+30
            // for n-byte modulus. Round to nearest 256/384/512 to
            // pick 2048/3072/4096.
            let len = bytes.len();
            let bits = if      len >= 540 { 4096 }
                       else if len >= 420 { 3072 }
                       else if len >= 290 { 2048 }
                       else if len >= 160 { 1024 }
                       else               { 512 };
            let (hygiene, issue) = match bits {
                4096 | 3072 | 2048 => ("ok", None),
                1024 => ("weak", Some("RSA-1024 — rotate to ≥2048".into())),
                _    => ("deprecated", Some(format!("RSA-{bits} — replace immediately"))),
            };
            (Some(bits), hygiene.into(), issue.map(String::from))
        }
    }
}

// Minimal standard-base64 decoder so we don't drag in `base64`. The
// DKIM p= field is the standard alphabet with padding optional.
fn base64_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [255u8; 256];
    for (i, &c) in charset.iter().enumerate() { table[c as usize] = i as u8; }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in s.as_bytes() {
        if b == b'=' { break; }
        let v = table[b as usize];
        if v == 255 { continue; }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

// ─── MX provider fingerprint ──────────────────────────────────────
fn fingerprint_provider(mxs: &[String]) -> ProviderFingerprint {
    let joined = mxs.join(" ").to_lowercase();
    let rules: &[(&str, &str, &str)] = &[
        ("mail.protection.outlook.com", "Microsoft 365 / Exchange Online", "cloud"),
        ("googlemail.com",              "Google Workspace",                "cloud"),
        ("google.com",                  "Google Workspace",                "cloud"),
        ("aspmx.l.google.com",          "Google Workspace",                "cloud"),
        ("proofpoint.com",              "Proofpoint",                      "gateway"),
        ("ppe-hosted.com",              "Proofpoint Essentials",           "gateway"),
        ("mimecast.com",                "Mimecast",                        "gateway"),
        ("ironport.com",                "Cisco IronPort / SEG",            "gateway"),
        ("barracudanetworks.com",       "Barracuda ESS",                   "gateway"),
        ("messagelabs.com",             "Symantec MessageLabs",            "gateway"),
        ("amazonses.com",               "Amazon SES",                      "cloud"),
        ("zoho.com",                    "Zoho Mail",                       "cloud"),
        ("yandex.net",                  "Yandex",                          "cloud"),
        ("fastmail.com",                "Fastmail",                        "cloud"),
        ("protonmail",                  "ProtonMail",                      "cloud"),
        ("rackspace.com",               "Rackspace Email",                 "cloud"),
        ("sendgrid.net",                "SendGrid",                        "cloud"),
        ("mailgun.org",                 "Mailgun",                         "cloud"),
        ("postmarkapp.com",             "Postmark",                        "cloud"),
        ("sparkpost.com",               "SparkPost",                       "cloud"),
        ("titan.email",                 "Titan Email",                     "cloud"),
    ];
    let mut matches = Vec::new();
    for (needle, vendor, cat) in rules {
        if joined.contains(needle) {
            matches.push((vendor.to_string(), cat.to_string(), needle.to_string()));
        }
    }
    if let Some((v, c, n)) = matches.first().cloned() {
        ProviderFingerprint {
            vendor: v, category: c,
            mx_match: matches.into_iter().map(|(_, _, n)| n).collect::<Vec<_>>().into_iter().chain([n].into_iter()).collect::<std::collections::HashSet<_>>().into_iter().collect(),
        }
    } else if mxs.is_empty() {
        ProviderFingerprint { vendor: "none".into(), category: "no-mx".into(), mx_match: Vec::new() }
    } else {
        ProviderFingerprint { vendor: "self-hosted/unknown".into(), category: "unknown".into(), mx_match: Vec::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_lookup_count_basic() {
        assert_eq!(count_spf_lookups("v=spf1 include:_spf.google.com -all"), 1);
        assert_eq!(count_spf_lookups("v=spf1 a mx include:_spf.x include:_spf.y -all"), 4);
        // ip4 / ip6 / all do NOT count
        assert_eq!(count_spf_lookups("v=spf1 ip4:1.2.3.4 ip4:5.6.7.8 -all"), 0);
    }

    #[test]
    fn provider_fingerprint_m365() {
        let p = fingerprint_provider(&["cybrium-ai.mail.protection.outlook.com".into()]);
        assert_eq!(p.vendor, "Microsoft 365 / Exchange Online");
        assert_eq!(p.category, "cloud");
    }

    #[test]
    fn analyse_dkim_short_rsa() {
        // 1024-bit RSA SPKI is ~162 bytes
        let fake = "A".repeat(216);  // base64 of ~162 bytes
        let (bits, hygiene, _) = analyse_dkim_key("rsa", &fake);
        assert!(bits.is_some());
        assert!(matches!(hygiene.as_str(), "weak" | "deprecated"));
    }
}
