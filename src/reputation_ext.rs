//! Sender Score + Cisco Talos reputation decorators (Sprint 98 P1 — v0.6.0).
//!
//! Both are **opt-in**: they decorate an existing ReputationReport
//! after the main reputation::run() finishes. If the operator hasn't
//! supplied the relevant env vars (Sender Score) or the network is
//! down (Talos), the decorator records a clear error in the
//! decorated fields and keeps the original report unchanged.
//!
//! Why a separate module? Keeps reputation.rs small + readable.
//! Easier to test these as standalone units. Future sources
//! (SpamhausIntel, AbuseIPDB, etc.) drop in here without touching
//! the main scanner.

use std::net::Ipv4Addr;
use std::time::Duration;

use hickory_resolver::Resolver;
use serde::{Deserialize, Serialize};

use crate::reputation::ReputationReport;

/// All Sender Score lookups (one per MX IP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderScoreResult {
    pub ip:        String,
    pub score:     Option<i32>,    // 0-100 if provider returned one
    pub error:     Option<String>,
}

/// Talos reputation for the apex domain (single record).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TalosResult {
    pub domain:           String,
    pub email_reputation: Option<String>,    // good / neutral / poor / unknown
    pub web_reputation:   Option<String>,
    pub category:         Option<String>,
    pub error:            Option<String>,
}

/// Bundle the decorator adds to the base ReputationReport. Stored on
/// the report under a single `extensions` key (additive — won't
/// collide with anything Cymail already emits).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReputationExtensions {
    pub sender_score:      Vec<SenderScoreResult>,
    pub talos_reputation:  Option<TalosResult>,
    pub queried_sources:   Vec<String>,
    pub skipped_sources:   Vec<String>,
}

pub struct ExtOpts {
    pub http_timeout:       Duration,
    pub sender_score_key:   Option<String>,
    pub use_talos:          bool,
}

impl Default for ExtOpts {
    fn default() -> Self {
        Self {
            http_timeout:       Duration::from_secs(8),
            sender_score_key:   std::env::var("SENDERSCORE_API_KEY").ok(),
            // Talos is a public web API, no key needed. Default on
            // so platform users get the extra signal automatically.
            use_talos:          true,
        }
    }
}

/// Decorate a ReputationReport with extension data. Idempotent — if
/// the report already has extensions, this overwrites them.
pub async fn decorate(report: &ReputationReport, opts: &ExtOpts) -> ReputationExtensions {
    let mut ext = ReputationExtensions::default();

    // Sender Score per MX IP — needs to resolve each MX to its IP set
    // first. The base ReputationReport already has mx_hosts; we
    // re-resolve here rather than depending on the caller passing
    // IPs (keeps the API simple).
    if opts.sender_score_key.is_some() {
        ext.queried_sources.push("senderscore".to_string());
        let mx_ips = resolve_all_mx_ips(&report.mx_hosts).await;
        let client_b = reqwest::Client::builder()
            .timeout(opts.http_timeout)
            .user_agent(format!("cymail/{}", env!("CARGO_PKG_VERSION")));
        if let Ok(client) = client_b.build() {
            for ip in mx_ips {
                ext.sender_score.push(senderscore_lookup(&client, ip,
                    opts.sender_score_key.as_deref().unwrap()).await);
            }
        }
    } else {
        ext.skipped_sources.push(
            "senderscore (set SENDERSCORE_API_KEY to enable)".to_string()
        );
    }

    // Talos — single apex-domain lookup; no key needed.
    if opts.use_talos {
        ext.queried_sources.push("talos".to_string());
        match talos_lookup(&report.domain, opts.http_timeout).await {
            Ok(r)  => ext.talos_reputation = Some(r),
            Err(e) => ext.talos_reputation = Some(TalosResult {
                domain:           report.domain.clone(),
                email_reputation: None,
                web_reputation:   None,
                category:         None,
                error:            Some(e),
            }),
        }
    } else {
        ext.skipped_sources.push("talos (opts.use_talos=false)".to_string());
    }

    ext
}

// ─── Sender Score ──────────────────────────────────────────────────
//
// Validity's Sender Score API: per-IP reputation 0-100. Requires an
// API key obtained from senderscore.org / Validity. The endpoint
// format here mirrors the documented shape:
//
//   GET https://api.senderscore.com/v1/sender-score/{ip}
//   Authorization: Bearer <key>
//   → { "ip": "1.2.3.4", "score": 87, ... }
//
// We're permissive on the response shape — the exact JSON layout
// has historically shifted. We pluck `score` (top-level or nested)
// and fall back to error on parse failure.

async fn senderscore_lookup(client: &reqwest::Client, ip: Ipv4Addr, key: &str) -> SenderScoreResult {
    let url = format!("https://api.senderscore.com/v1/sender-score/{ip}");
    let resp = match client.get(&url).bearer_auth(key).send().await {
        Ok(r) => r,
        Err(e) => return SenderScoreResult {
            ip: ip.to_string(), score: None,
            error: Some(format!("request failed: {e}")),
        },
    };
    let status = resp.status();
    if !status.is_success() {
        return SenderScoreResult {
            ip: ip.to_string(), score: None,
            error: Some(format!("HTTP {status}")),
        };
    }
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let score = body.get("score").and_then(|v| v.as_i64())
        .or_else(|| body.get("data").and_then(|d| d.get("score")).and_then(|v| v.as_i64()))
        .map(|n| n as i32);
    SenderScoreResult {
        ip:    ip.to_string(),
        score,
        error: if score.is_none() { Some("score field missing".to_string()) } else { None },
    }
}

// ─── Cisco Talos ───────────────────────────────────────────────────
//
// Public web API used by talosintelligence.com's lookup tool. Form-
// encoded POST to `/sb_api/query_lookup`. Returns JSON with email +
// web reputation strings (Good / Neutral / Poor / Unknown) plus a
// category classifier.
//
// No auth, no key. Rate limit is generous (~10 req/s sustained).

async fn talos_lookup(domain: &str, timeout: Duration) -> Result<TalosResult, String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(format!("cymail/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("client build: {e}"))?;
    let url  = "https://talosintelligence.com/sb_api/query_lookup";
    let body = [
        ("query_type",  "url"),
        ("query_entry", domain),
        ("offset",      "0"),
    ];
    let resp = client.post(url).form(&body).send().await
        .map_err(|e| format!("request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let j: serde_json::Value = resp.json().await.map_err(|e| format!("json parse: {e}"))?;

    // Talos schema: { "entries": [ { "email_score_name": "Neutral", ... } ] }
    // Older shape used `web_score_name` / `email_reputation` at top level.
    // We probe both.
    let pick = |keys: &[&str]| -> Option<String> {
        for k in keys {
            if let Some(s) = j.get(*k).and_then(|v| v.as_str()) {
                return Some(s.to_string());
            }
            if let Some(first) = j.get("entries").and_then(|e| e.as_array()).and_then(|a| a.first()) {
                if let Some(s) = first.get(*k).and_then(|v| v.as_str()) {
                    return Some(s.to_string());
                }
            }
        }
        None
    };
    Ok(TalosResult {
        domain:           domain.to_string(),
        email_reputation: pick(&["email_score_name", "email_reputation"]),
        web_reputation:   pick(&["web_score_name", "web_reputation"]),
        category:         pick(&["category", "threat_category"]),
        error:            None,
    })
}

// ─── Helpers ──────────────────────────────────────────────────────
async fn resolve_all_mx_ips(mxs: &[String]) -> Vec<Ipv4Addr> {
    let Ok(builder) = Resolver::builder_tokio() else { return Vec::new(); };
    let resolver = builder.build();
    let mut out = Vec::new();
    for mx in mxs {
        if let Ok(resp) = resolver.ipv4_lookup(mx).await {
            for ip in resp.iter() {
                out.push(Ipv4Addr::from(ip.0));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opts_default_no_panic() {
        let _o = ExtOpts::default();
    }

    #[test]
    fn extensions_default_is_empty() {
        let e = ReputationExtensions::default();
        assert!(e.sender_score.is_empty());
        assert!(e.talos_reputation.is_none());
    }
}
