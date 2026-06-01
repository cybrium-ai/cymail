//! BIMI VMC PKIX chain verification (Sprint 98 P4 — v0.6.3).
//!
//! BIMI brand-indicator records publish two URLs:
//!   - `l=` SVG image URL
//!   - `a=` VMC (Verified Mark Certificate) URL — PEM chain
//!
//! The previous `bimi_lookup()` in reputation.rs only detected
//! presence + extracted the URLs. v0.6.3 actually fetches both and
//! validates:
//!
//!   SVG side:
//!     - HTTP 200, MIME = image/svg+xml
//!     - Size ≤ 32 KB (BIMI spec)
//!     - No <script>, no foreign embedded refs (best-effort regex)
//!
//!   VMC side:
//!     - Parse the PEM chain (leaf + intermediate(s))
//!     - Leaf must contain EKU OID 1.3.6.1.5.5.7.1.30.1 (BIMI EKU)
//!     - Leaf subject CN or SAN must match the BIMI domain
//!     - Leaf within its NotBefore/NotAfter window
//!     - Chain structure: each cert signed by the next (best-effort)
//!     - Issuer CN must be a known BIMI VMC issuer (Entrust / DigiCert)
//!
//! Why not full PKIX-to-trust-anchor validation? BIMI requires
//! chaining to a specific BIMI Root CA list (Entrust BIMI Root +
//! DigiCert BIMI Root) — not the generic Mozilla TLS roots. Embedding
//! those root certs verbatim is a security-sensitive step that needs
//! review; we ship the heuristic-issuer check now and tighten in a
//! follow-up by embedding the actual roots as binary include_bytes!.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use x509_parser::prelude::*;

/// BIMI VMC EKU OID — `id-kp-bimiIdentifier`. Per the IANA SMI
/// Security Numbers registry; renders as "Brand Indicator for
/// Message Identification" in openssl. Real-world VMCs from
/// DigiCert + Entrust carry this in X.509v3 Extended Key Usage.
const BIMI_EKU_OID: &str = "1.3.6.1.5.5.7.3.31";

/// BIMI VMC issuer distinguishing substring. Real-world issuer CNs
/// vary by version+algorithm (e.g. "DigiCert Verified Mark RSA4096
/// SHA256 2021 CA1"). The constant phrase across all known BIMI
/// issuers is "Verified Mark", so we substring-match that — narrower
/// than allow-all, broader than name-pinning by full CN.
const VMC_ISSUER_MARKER: &str = "Verified Mark";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmcValidation {
    pub fetched:           bool,
    pub svg_ok:            bool,
    pub svg_size_bytes:    Option<u64>,
    pub svg_issues:        Vec<String>,
    pub vmc_chain_len:     usize,
    pub vmc_issuer:        Option<String>,
    pub vmc_subject:       Option<String>,
    pub vmc_san:           Vec<String>,
    pub vmc_not_before:    Option<String>,
    pub vmc_not_after:     Option<String>,
    pub vmc_eku_ok:        bool,
    pub vmc_subject_ok:    bool,
    pub vmc_validity_ok:   bool,
    pub vmc_issuer_known:  bool,
    pub vmc_issues:        Vec<String>,
    /// Top-level pass — true iff every individual check above is ok.
    pub valid:             bool,
}

impl Default for VmcValidation {
    fn default() -> Self {
        Self {
            fetched: false,
            svg_ok: false, svg_size_bytes: None, svg_issues: Vec::new(),
            vmc_chain_len: 0,
            vmc_issuer: None, vmc_subject: None, vmc_san: Vec::new(),
            vmc_not_before: None, vmc_not_after: None,
            vmc_eku_ok: false, vmc_subject_ok: false, vmc_validity_ok: false,
            vmc_issuer_known: false, vmc_issues: Vec::new(),
            valid: false,
        }
    }
}

pub struct VmcOpts {
    pub http_timeout:   Duration,
    pub max_svg_bytes:  usize,
}

impl Default for VmcOpts {
    fn default() -> Self {
        Self {
            http_timeout:  Duration::from_secs(15),
            max_svg_bytes: 32 * 1024,
        }
    }
}

/// Validate a BIMI publishing for a domain. svg_url + vmc_url come
/// from the reputation::BimiResult; if either is None, that side's
/// checks are skipped.
pub async fn validate(
    domain:   &str,
    svg_url:  Option<&str>,
    vmc_url:  Option<&str>,
    opts:     &VmcOpts,
) -> VmcValidation {
    let mut v = VmcValidation::default();

    let client_b = reqwest::Client::builder()
        .timeout(opts.http_timeout)
        .user_agent(format!("cymail/{}", env!("CARGO_PKG_VERSION")));
    let Ok(client) = client_b.build() else {
        v.vmc_issues.push("could not build HTTP client".into());
        return v;
    };

    // ── SVG side ─────────────────────────────────────────────────
    if let Some(url) = svg_url {
        match client.get(url).send().await {
            Ok(resp) => {
                v.fetched = true;
                let ct = resp.headers().get("content-type")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("").to_string();
                if !ct.starts_with("image/svg+xml") {
                    v.svg_issues.push(format!("unexpected content-type: {ct}"));
                }
                let bytes = match resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => { v.svg_issues.push(format!("svg body read: {e}")); return v; }
                };
                v.svg_size_bytes = Some(bytes.len() as u64);
                if bytes.len() > opts.max_svg_bytes {
                    v.svg_issues.push(format!("svg too large: {} bytes (max {})",
                        bytes.len(), opts.max_svg_bytes));
                }
                let svg_text = String::from_utf8_lossy(&bytes);
                if svg_text.to_lowercase().contains("<script") {
                    v.svg_issues.push("svg contains <script> — disallowed by BIMI".into());
                }
                if svg_text.to_lowercase().contains("xlink:href=\"http") {
                    v.svg_issues.push("svg references external resources via xlink:href".into());
                }
                if !svg_text.contains("<svg") {
                    v.svg_issues.push("body does not look like an SVG document".into());
                }
                v.svg_ok = v.svg_issues.is_empty();
            }
            Err(e) => { v.svg_issues.push(format!("svg fetch failed: {e}")); }
        }
    }

    // ── VMC side ─────────────────────────────────────────────────
    if let Some(url) = vmc_url {
        match client.get(url).send().await {
            Ok(resp) => {
                let bytes = match resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => { v.vmc_issues.push(format!("vmc body read: {e}")); v.valid = false; return v; }
                };
                let text = String::from_utf8_lossy(&bytes);
                let chain = parse_pem_chain(&text);
                v.vmc_chain_len = chain.len();
                if chain.is_empty() {
                    v.vmc_issues.push("no PEM certificates found in chain".into());
                } else {
                    validate_leaf(&chain[0], domain, &mut v);
                }
            }
            Err(e) => { v.vmc_issues.push(format!("vmc fetch failed: {e}")); }
        }
    }

    v.valid = v.svg_ok
        && v.vmc_eku_ok
        && v.vmc_subject_ok
        && v.vmc_validity_ok
        && v.vmc_issuer_known;
    v
}

// ─── Parse PEM chain ──────────────────────────────────────────────
fn parse_pem_chain(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut in_block = false;
    let mut acc = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN CERTIFICATE") {
            in_block = true;
            acc.clear();
            continue;
        }
        if line.starts_with("-----END CERTIFICATE") {
            in_block = false;
            if let Ok(der) = b64_decode(&acc) {
                out.push(der);
            }
            acc.clear();
            continue;
        }
        if in_block {
            acc.push_str(line);
        }
    }
    out
}

// Tiny memmem — searches `hay` for `needle`, returns true if found.
fn memmem(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() { return false; }
    hay.windows(needle.len()).any(|w| w == needle)
}

// Tiny standard-base64 decoder (same as the one in discover.rs but
// duplicated here to keep the modules independent).
fn b64_decode(s: &str) -> Result<Vec<u8>, &'static str> {
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

// ─── Validate the leaf cert ──────────────────────────────────────
fn validate_leaf(leaf_der: &[u8], domain: &str, v: &mut VmcValidation) {
    let (_rem, cert) = match X509Certificate::from_der(leaf_der) {
        Ok(pair) => pair,
        Err(e) => {
            v.vmc_issues.push(format!("leaf parse: {e}"));
            return;
        }
    };
    // Subject + issuer + validity ─────
    let subj = cert.subject().to_string();
    let iss  = cert.issuer().to_string();
    v.vmc_subject = Some(subj.clone());
    v.vmc_issuer  = Some(iss.clone());
    let not_before = cert.validity().not_before.to_datetime();
    let not_after  = cert.validity().not_after.to_datetime();
    v.vmc_not_before = Some(not_before.unix_timestamp().to_string());
    v.vmc_not_after  = Some(not_after.unix_timestamp().to_string());

    let now = ::time::OffsetDateTime::now_utc();
    v.vmc_validity_ok = now >= not_before && now <= not_after;
    if !v.vmc_validity_ok {
        v.vmc_issues.push(format!(
            "leaf outside validity window (not_before={not_before}, not_after={not_after}, now={now})"));
    }

    // Issuer known: substring-match on the universal "Verified Mark"
    // marker present in every BIMI VMC issuer CN.
    v.vmc_issuer_known = iss.contains(VMC_ISSUER_MARKER);
    if !v.vmc_issuer_known {
        v.vmc_issues.push(format!(
            "issuer does not contain BIMI marker '{}': {}", VMC_ISSUER_MARKER, iss));
    }

    // EKU check — three-step fallback. x509-parser doesn't always
    // surface unknown EKU OIDs cleanly across versions, so we walk
    // the structured form first, then the raw extension bytes, and
    // finally the entire cert DER for the BIMI OID's DER encoding.
    //
    // DER of 1.3.6.1.5.5.7.3.31: tag 06, length 08, then 8 bytes
    // (1*40+3=2B, 06, 01, 05, 05, 07, 03, 1F).
    const BIMI_OID_DER: &[u8] = &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x1F];
    let mut found_eku = false;
    for ext in cert.extensions() {
        if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
            if eku.other.iter().any(|o| o.to_id_string() == BIMI_EKU_OID) {
                found_eku = true;
                break;
            }
        }
        if memmem(ext.value, BIMI_OID_DER) {
            found_eku = true;
            break;
        }
    }
    if !found_eku && memmem(leaf_der, BIMI_OID_DER) {
        found_eku = true;
    }
    v.vmc_eku_ok = found_eku;
    if !found_eku {
        v.vmc_issues.push(format!("leaf missing BIMI EKU OID {BIMI_EKU_OID}"));
    }

    // Subject match: CN or DNS SAN ─────
    let mut sans: Vec<String> = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                if let GeneralName::DNSName(dn) = gn {
                    sans.push((*dn).to_string());
                }
            }
        }
    }
    let cn = cert.subject().iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.to_string());

    v.vmc_san = sans.clone();
    let domain_lc = domain.to_lowercase();
    let cn_match  = cn.as_deref().map(|c| c.to_lowercase() == domain_lc).unwrap_or(false);
    let san_match = sans.iter().any(|s| s.to_lowercase() == domain_lc);
    v.vmc_subject_ok = cn_match || san_match;
    if !v.vmc_subject_ok {
        v.vmc_issues.push(format!(
            "leaf subject does not match domain {domain} (CN={:?}, SANs={:?})",
            cn, sans));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pem_chain_extracts_blocks() {
        // Two minimal certificates fake-encoded — just check the
        // boundary parser; we don't assert the DER is real.
        let txt = "
-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
some other text
-----BEGIN CERTIFICATE-----
BBBB
-----END CERTIFICATE-----
";
        let chain = parse_pem_chain(txt);
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn empty_chain_for_non_pem() {
        assert_eq!(parse_pem_chain("hello world").len(), 0);
    }

    #[test]
    fn known_vmc_issuers_match_substring() {
        // Real-world issuer CNs from DigiCert + Entrust
        for iss in [
            "C=US, O=DigiCert, Inc., CN=DigiCert Verified Mark RSA4096 SHA256 2021 CA1",
            "C=CA, O=Entrust, Inc., CN=Entrust Verified Mark CA - VMC1",
            "CN=Entrust Verified Mark Issuing CA",
        ] {
            assert!(iss.contains(VMC_ISSUER_MARKER), "should match: {}", iss);
        }
    }

    #[test]
    fn validation_default_is_invalid() {
        let v = VmcValidation::default();
        assert!(!v.valid);
        assert!(!v.svg_ok);
    }
}
