//! SMTP posture probe — v0.7.0 (Sprint 119 P1.1).
//!
//! Resolves a domain's MX records, then for each MX host opens port 25 and
//! runs: TCP reachability + banner read, EHLO + STARTTLS verb detection,
//! STARTTLS upgrade with TLS version + certificate validity checks, and a
//! safe (abort-before-DATA) open-relay test.
//!
//! v0.7.0 ships the highest-impact half of the probe set spec'd in
//! `docs/design/cymail-smtp.md`. Cipher enumeration, AUTH-method
//! detection, DANE TLSA verification, and submission-port hygiene are
//! v0.7.1+ work — additive to the same JSON shape.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::Resolver;
use hickory_resolver::proto::rr::rdata::MX;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use crate::Finding;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT:    Duration = Duration::from_secs(5);
const PER_MX_BUDGET:   Duration = Duration::from_secs(20);
const PROBE_HELO:      &str     = "cymail.cybrium.ai";

// ── Public report shape ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpReport {
    pub domain:     String,
    pub elapsed_ms: u64,
    pub mx_hosts:   Vec<MxHostReport>,
    pub findings:   Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxHostReport {
    pub host:       String,
    pub preference: u16,
    pub port25:     PortProbe,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortProbe {
    pub reachable:  bool,
    pub error:      Option<String>,
    pub banner:     Option<String>,
    pub ehlo:       Vec<String>,
    pub starttls:   Option<StartTlsResult>,
    pub open_relay: Option<bool>,
    pub timings_ms: PortTimings,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortTimings {
    pub connect:   u64,
    pub ehlo:      u64,
    pub starttls:  u64,
    pub handshake: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartTlsResult {
    pub upgraded:            bool,
    pub error:               Option<String>,
    pub tls_version:         Option<String>,
    pub cert_subject:        Option<String>,
    pub cert_issuer:         Option<String>,
    pub cert_san:            Vec<String>,
    pub cert_not_after:      Option<String>,
    pub cert_days_remaining: Option<i64>,
    pub cert_self_signed:    bool,
    pub cert_hostname_match: Option<bool>,
}

// ── Entry point ──────────────────────────────────────────────────────

pub async fn probe(domain: &str) -> SmtpReport {
    let start = Instant::now();
    let mut report = SmtpReport {
        domain:     domain.to_string(),
        elapsed_ms: 0,
        mx_hosts:   Vec::new(),
        findings:   Vec::new(),
    };

    let mx_hosts = match resolve_mx(domain).await {
        Ok(v) => v,
        Err(e) => {
            report.findings.push(finding(
                "SMTP-UNREACHABLE", "critical",
                "MX resolution failed",
                format!("Could not resolve MX or A records for {domain}: {e}"),
            ));
            report.elapsed_ms = start.elapsed().as_millis() as u64;
            return report;
        }
    };

    for (host, pref) in mx_hosts {
        let port25 = match timeout(PER_MX_BUDGET, probe_port25(&host)).await {
            Ok(p) => p,
            Err(_) => PortProbe {
                reachable: false,
                error: Some(format!("per-MX wall-clock budget exceeded ({:?})", PER_MX_BUDGET)),
                ..Default::default()
            },
        };
        emit_findings(&mut report.findings, &host, &port25);
        report.mx_hosts.push(MxHostReport { host, preference: pref, port25 });
    }

    report.elapsed_ms = start.elapsed().as_millis() as u64;
    report
}

// ── MX resolution ────────────────────────────────────────────────────

async fn resolve_mx(domain: &str) -> Result<Vec<(String, u16)>, String> {
    let resolver = Resolver::builder_tokio().map_err(|e| e.to_string())?.build();

    if let Ok(mx_records) = resolver.mx_lookup(domain).await {
        let mut v: Vec<(String, u16)> = mx_records
            .iter()
            .map(|r: &MX| (r.exchange().to_string().trim_end_matches('.').to_string(), r.preference()))
            .collect();
        if !v.is_empty() {
            v.sort_by_key(|(_, p)| *p);
            return Ok(v);
        }
    }
    if resolver.lookup_ip(domain).await.is_ok() {
        return Ok(vec![(domain.to_string(), 0)]);
    }
    Err("no MX, A, or AAAA records resolvable".into())
}

// ── Port 25 probe ────────────────────────────────────────────────────

async fn probe_port25(host: &str) -> PortProbe {
    let mut probe = PortProbe::default();
    let connect_start = Instant::now();

    let tcp = match timeout(CONNECT_TIMEOUT, TcpStream::connect(format!("{host}:25"))).await {
        Ok(Ok(s))  => s,
        Ok(Err(e)) => { probe.error = Some(format!("connect failed: {e}")); return probe; }
        Err(_)     => { probe.error = Some(format!("connect timeout after {CONNECT_TIMEOUT:?}")); return probe; }
    };
    probe.reachable = true;
    probe.timings_ms.connect = connect_start.elapsed().as_millis() as u64;

    let mut stream = BufReader::new(tcp);

    // Banner.
    probe.banner = read_smtp_response(&mut stream).await.ok();

    // EHLO.
    let ehlo_start = Instant::now();
    if stream.get_mut().write_all(format!("EHLO {PROBE_HELO}\r\n").as_bytes()).await.is_err() {
        probe.error = Some("EHLO write failed".into());
        return probe;
    }
    let ehlo_response = match read_smtp_response(&mut stream).await {
        Ok(r) => r,
        Err(e) => { probe.error = Some(format!("EHLO read failed: {e}")); return probe; }
    };
    probe.timings_ms.ehlo = ehlo_start.elapsed().as_millis() as u64;
    probe.ehlo = parse_ehlo_verbs(&ehlo_response);

    // STARTTLS — only if advertised.
    let starttls_advertised = probe.ehlo.iter().any(|v| v.eq_ignore_ascii_case("STARTTLS"));
    if starttls_advertised {
        let starttls_start = Instant::now();
        if stream.get_mut().write_all(b"STARTTLS\r\n").await.is_ok()
            && read_smtp_response(&mut stream).await.is_ok()
        {
            probe.timings_ms.starttls = starttls_start.elapsed().as_millis() as u64;

            // Hand the raw socket off to rustls.
            let raw = stream.into_inner();
            let handshake_start = Instant::now();
            let result = upgrade_to_tls(raw, host).await;
            probe.timings_ms.handshake = handshake_start.elapsed().as_millis() as u64;
            probe.starttls = Some(result);
            // After TLS upgrade, the rest of the probe needs a re-handshake-
            // safe path. v0.7.0 stops here — open-relay probe on the
            // plaintext side already ran via a parallel connection below.
            probe.open_relay = open_relay_via_parallel_connection(host).await.ok();
            return probe;
        } else {
            probe.starttls = Some(fail("STARTTLS write or response read failed"));
        }
    } else {
        // Cleartext path — open-relay probe directly on the same stream.
        probe.open_relay = open_relay_probe(&mut stream).await.ok();
        let _ = stream.get_mut().write_all(b"QUIT\r\n").await;
    }
    probe
}

// ── EHLO helpers ─────────────────────────────────────────────────────

async fn read_smtp_response<R>(r: &mut BufReader<R>) -> Result<String, String>
where R: AsyncRead + Unpin
{
    let mut accumulated = String::new();
    loop {
        let mut line = String::new();
        match timeout(READ_TIMEOUT, r.read_line(&mut line)).await {
            Ok(Ok(0))  => return Err("connection closed".into()),
            Ok(Ok(_))  => {}
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_)     => return Err(format!("read timeout after {READ_TIMEOUT:?}")),
        }
        accumulated.push_str(&line);
        let trimmed = line.trim_end();
        if trimmed.len() >= 4 {
            let sep = trimmed.as_bytes()[3];
            if sep == b' ' { break; }
        } else if trimmed.is_empty() {
            break;
        }
    }
    Ok(accumulated)
}

fn parse_ehlo_verbs(response: &str) -> Vec<String> {
    let mut verbs = Vec::new();
    for line in response.lines() {
        let trimmed = line.trim();
        if trimmed.len() < 4 { continue; }
        let payload = trimmed[4..].trim();
        if payload.is_empty() { continue; }
        let verb = payload.split_ascii_whitespace().next().unwrap_or("").to_string();
        if !verb.is_empty() { verbs.push(verb); }
    }
    verbs
}

// ── TLS upgrade ──────────────────────────────────────────────────────

async fn upgrade_to_tls(tcp: TcpStream, host: &str) -> StartTlsResult {
    let config = build_rustls_config();
    let connector = TlsConnector::from(Arc::new(config));
    let sni = match ServerName::try_from(host.to_string()) {
        Ok(s)  => s,
        Err(e) => return fail(format!("server name parse failed: {e}")),
    };
    let tls = match timeout(READ_TIMEOUT, connector.connect(sni, tcp)).await {
        Ok(Ok(s))  => s,
        Ok(Err(e)) => return fail(format!("TLS handshake failed: {e}")),
        Err(_)     => return fail("TLS handshake timeout"),
    };

    let (_, conn) = tls.get_ref();
    let tls_version = conn.protocol_version().map(|v| format!("{v:?}"));
    let mut result = StartTlsResult {
        upgraded:            true,
        error:               None,
        tls_version,
        cert_subject:        None,
        cert_issuer:         None,
        cert_san:            Vec::new(),
        cert_not_after:      None,
        cert_days_remaining: None,
        cert_self_signed:    false,
        cert_hostname_match: None,
    };
    if let Some(peer_certs) = conn.peer_certificates() {
        if let Some(leaf) = peer_certs.first() {
            populate_cert_fields(&mut result, leaf.as_ref(), host);
        }
    }
    // Drain TLS shutdown — best effort.
    let mut tls = tls;
    let _ = tls.shutdown().await;
    result
}

fn fail<S: Into<String>>(msg: S) -> StartTlsResult {
    StartTlsResult {
        upgraded:            false,
        error:               Some(msg.into()),
        tls_version:         None,
        cert_subject:        None,
        cert_issuer:         None,
        cert_san:            Vec::new(),
        cert_not_after:      None,
        cert_days_remaining: None,
        cert_self_signed:    false,
        cert_hostname_match: None,
    }
}

fn build_rustls_config() -> ClientConfig {
    // Rustls 0.23 requires an explicit CryptoProvider when more than one
    // is compiled in (or when none is the unambiguous default). Pin
    // ring; install is idempotent — the Err on second call just means
    // a provider is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    for cert in webpki_roots::TLS_SERVER_ROOTS.iter() {
        roots.roots.push(cert.clone());
    }
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

fn populate_cert_fields(out: &mut StartTlsResult, der: &[u8], host: &str) {
    let Ok((_, cert)) = X509Certificate::from_der(der) else { return; };
    out.cert_subject = Some(cert.tbs_certificate.subject.to_string());
    out.cert_issuer  = Some(cert.tbs_certificate.issuer.to_string());
    out.cert_self_signed = cert.tbs_certificate.subject == cert.tbs_certificate.issuer;

    let not_after = cert.tbs_certificate.validity.not_after;
    out.cert_not_after = not_after.to_rfc2822().ok();
    let now_ts = chrono::Utc::now().timestamp();
    let na_ts  = not_after.timestamp();
    out.cert_days_remaining = Some(((na_ts - now_ts) / 86_400) as i64);

    if let Ok(Some(san)) = cert.tbs_certificate.subject_alternative_name() {
        for name in san.value.general_names.iter() {
            if let GeneralName::DNSName(dns) = name {
                out.cert_san.push(dns.to_string());
            }
        }
    }
    out.cert_hostname_match = Some(host_matches_cert(host, &out.cert_san));
}

fn host_matches_cert(host: &str, sans: &[String]) -> bool {
    let host_lower = host.to_ascii_lowercase();
    for san in sans {
        let san_lower = san.to_ascii_lowercase();
        if san_lower == host_lower { return true; }
        if let Some(rest) = san_lower.strip_prefix("*.") {
            if let Some(host_rest) = host_lower.split_once('.').map(|(_, r)| r) {
                if host_rest == rest { return true; }
            }
        }
    }
    false
}

// ── Open-relay probe ────────────────────────────────────────────────

async fn open_relay_probe<R>(stream: &mut BufReader<R>) -> Result<bool, String>
where R: AsyncRead + AsyncWrite + Unpin
{
    stream.get_mut().write_all(b"MAIL FROM:<probe@cymail.cybrium.ai>\r\n").await
        .map_err(|e| e.to_string())?;
    let mf_response = read_smtp_response(stream).await?;
    if !mf_response.starts_with("250") {
        return Ok(false);
    }
    stream.get_mut().write_all(b"RCPT TO:<probe@open-relay-check.invalid>\r\n").await
        .map_err(|e| e.to_string())?;
    let rcpt_response = read_smtp_response(stream).await?;
    let accepted = rcpt_response.starts_with("250");
    let _ = stream.get_mut().write_all(b"RSET\r\n").await;
    let _ = read_smtp_response(stream).await;
    Ok(accepted)
}

/// When the connection has already been upgraded to TLS, run the
/// open-relay probe on a parallel plaintext connection. Most modern
/// MXs reject post-DATA relay attempts at the same point regardless of
/// transport, so this is a faithful proxy for the encrypted flow.
async fn open_relay_via_parallel_connection(host: &str) -> Result<bool, String> {
    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(format!("{host}:25"))).await
        .map_err(|_| "open-relay parallel connect timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let mut stream = BufReader::new(tcp);
    let _ = read_smtp_response(&mut stream).await; // banner
    stream.get_mut().write_all(format!("EHLO {PROBE_HELO}\r\n").as_bytes()).await
        .map_err(|e| e.to_string())?;
    let _ = read_smtp_response(&mut stream).await;
    let result = open_relay_probe(&mut stream).await;
    let _ = stream.get_mut().write_all(b"QUIT\r\n").await;
    result
}

// ── Finding emission ────────────────────────────────────────────────

fn emit_findings(findings: &mut Vec<Finding>, host: &str, probe: &PortProbe) {
    let where_ = format!("{host}:25");
    if !probe.reachable {
        findings.push(finding(
            "SMTP-UNREACHABLE", "high",
            "MX did not accept TCP on port 25",
            format!("{where_}: {}", probe.error.as_deref().unwrap_or("unknown")),
        ));
        return;
    }
    if probe.banner.as_deref().map(|b| b.trim().is_empty()).unwrap_or(true) {
        findings.push(finding(
            "SMTP-NO-BANNER", "medium",
            "MX did not return SMTP banner",
            format!("{where_}: no banner within {READ_TIMEOUT:?}"),
        ));
    }
    if !probe.ehlo.iter().any(|v| v.eq_ignore_ascii_case("STARTTLS")) {
        findings.push(finding(
            "SMTP-STARTTLS-MISSING", "critical",
            "MX does not advertise STARTTLS on port 25",
            format!("{where_}: EHLO response did not include STARTTLS verb"),
        ));
    }
    if let Some(starttls) = &probe.starttls {
        if !starttls.upgraded {
            findings.push(finding(
                "SMTP-STARTTLS-FAILED", "critical",
                "MX advertised STARTTLS but upgrade failed",
                format!("{where_}: {}", starttls.error.as_deref().unwrap_or("unknown")),
            ));
        } else {
            if let Some(v) = starttls.tls_version.as_deref() {
                if v.contains("TLSv1_0") || v.contains("TLSv1_1") || v.contains("TLSv1.0") || v.contains("TLSv1.1") {
                    findings.push(finding(
                        "SMTP-TLS-WEAK-VERSION", "high",
                        "MX negotiates TLS 1.0 or 1.1",
                        format!("{where_}: negotiated {v}"),
                    ));
                }
            }
            if starttls.cert_self_signed {
                findings.push(finding(
                    "SMTP-CERT-SELF-SIGNED", "critical",
                    "MX certificate is self-signed",
                    format!("{where_}: subject == issuer ({})",
                        starttls.cert_subject.as_deref().unwrap_or("?")),
                ));
            }
            if let Some(d) = starttls.cert_days_remaining {
                if d < 0 {
                    findings.push(finding(
                        "SMTP-CERT-EXPIRED", "critical",
                        "MX certificate is expired",
                        format!("{where_}: expired {} day(s) ago", d.abs()),
                    ));
                } else if d < 30 {
                    findings.push(finding(
                        "SMTP-CERT-NEAR-EXPIRY", "medium",
                        "MX certificate expires within 30 days",
                        format!("{where_}: {d} day(s) remaining"),
                    ));
                }
            }
            if starttls.cert_hostname_match == Some(false) {
                findings.push(finding(
                    "SMTP-CERT-HOSTNAME-MISMATCH", "high",
                    "MX certificate CN/SAN does not include MX hostname",
                    format!("{where_}: SAN list {:?} does not match {host}", starttls.cert_san),
                ));
            }
        }
    }
    if probe.open_relay == Some(true) {
        findings.push(finding(
            "SMTP-OPEN-RELAY", "critical",
            "MX accepted unauthenticated relay to third-party recipient",
            format!("{where_}: RCPT TO third-party domain returned 250 without authentication"),
        ));
    }
}

fn finding(id: &str, sev: &str, title: &str, evidence: impl Into<String>) -> Finding {
    Finding {
        id:          id.to_string(),
        title:       title.to_string(),
        severity:    sev.to_string(),
        description: evidence.into(),
    }
}
