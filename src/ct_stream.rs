//! Real-time CT log streaming (Sprint 98 P2 — v0.6.1).
//!
//! Replaces the per-variant crt.sh poll in `cymail leak` with a
//! push-based subscription to **CertStream** (Cali Dog Security).
//! Every certificate published to *any* public CT log appears as a
//! JSON message on the WS; we filter against the lookalike set and
//! emit one line per match.
//!
//! Default `cymail leak` (no --watch) still polls crt.sh — the
//! existing scriptable behaviour is preserved. `--watch` is a new,
//! additive operator mode for continuous monitoring.
//!
//! WS URL: wss://certstream.calidog.io
//! No auth. Public. Best-effort reconnect on disconnect.

use std::collections::HashSet;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite, MaybeTlsStream, WebSocketStream};

use crate::leak::generate_lookalikes;

/// One event we emit per match. Stable JSON shape so consumers can
/// pipe to jq or ship to a SIEM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertstreamHit {
    pub source_domain:   String,            // the domain the operator asked about
    pub matched:         String,            // the lookalike that hit
    pub variant_type:    String,            // homoglyph / typo / etc.
    pub cert_subject:    String,            // CN= of the cert (or empty)
    pub cert_san:        Vec<String>,       // all matching SANs on the cert
    pub issuer:          String,
    pub not_before:      Option<String>,
    pub log_url:         Option<String>,
    pub seen_at:         String,
}

pub struct WatchOpts {
    pub url:          String,
    pub max_runtime:  Option<Duration>,    // None = run forever
    pub reconnect:    bool,
}

impl Default for WatchOpts {
    fn default() -> Self {
        Self {
            url:          "wss://certstream.calidog.io".to_string(),
            max_runtime:  None,
            reconnect:    true,
        }
    }
}

/// Long-running watcher. Emits each CertstreamHit through `on_hit`.
/// The callback is sync so it can println! / append to a file
/// without dragging async-trait into the surface.
pub async fn watch<F>(domain: &str, opts: &WatchOpts, mut on_hit: F) -> Result<(), String>
where
    F: FnMut(CertstreamHit),
{
    // Build the lookalike match set once. We compare the cert's
    // SAN list against this set on every message.
    let variants = generate_lookalikes(domain);
    let mut variant_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for (v, kind) in &variants {
        variant_map.insert(v.to_lowercase(), kind.clone());
    }
    // Also include the source domain itself so the operator sees
    // certs issued for THEIR domain (legitimate or otherwise).
    variant_map.insert(domain.to_lowercase(), "source".into());

    let needle_set: HashSet<&str> = variant_map.keys().map(|s| s.as_str()).collect();
    eprintln!("  watching {} variants over CertStream (Ctrl-C to stop)", needle_set.len());

    let started = std::time::Instant::now();
    loop {
        if let Some(cap) = opts.max_runtime {
            if started.elapsed() >= cap {
                eprintln!("  watch: max_runtime reached, exiting");
                return Ok(());
            }
        }

        let (mut ws, _resp) = match connect_async(&opts.url).await {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("WS connect failed: {e}");
                if !opts.reconnect { return Err(msg); }
                eprintln!("  {msg}; retrying in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        // Stream messages until disconnect, then reconnect.
        let r = read_loop(&mut ws, &variant_map, domain, &mut on_hit).await;
        if let Err(e) = r {
            if !opts.reconnect { return Err(e); }
            eprintln!("  {e}; reconnecting in 5s");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

async fn read_loop<F>(
    ws:           &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    variant_map:  &std::collections::HashMap<String, String>,
    domain:       &str,
    on_hit:       &mut F,
) -> Result<(), String>
where
    F: FnMut(CertstreamHit),
{
    while let Some(msg) = ws.next().await {
        let msg = msg.map_err(|e| format!("WS read: {e}"))?;
        match msg {
            tungstenite::Message::Ping(p) => {
                let _ = ws.send(tungstenite::Message::Pong(p)).await;
            }
            tungstenite::Message::Text(text) => {
                if let Some(hit) = parse_certstream_message(&text, variant_map, domain) {
                    on_hit(hit);
                }
            }
            tungstenite::Message::Close(_) => {
                return Err("WS closed by peer".into());
            }
            _ => {}
        }
    }
    Err("WS stream ended".into())
}

/// Parse one CertStream message + emit a hit if any SAN matches the
/// lookalike set. Returns at most one hit per message (the first
/// match) to keep the output stream readable; we record all matching
/// SANs in the same hit struct.
///
/// CertStream message shape (current schema):
/// ```json
/// {
///   "message_type": "certificate_update",
///   "data": {
///     "cert_index": 123,
///     "cert_link":  "https://...",
///     "leaf_cert": {
///       "all_domains":   ["foo.com", "*.foo.com"],
///       "subject":       { "CN": "foo.com", ... },
///       "issuer":        { "CN": "DigiCert ...", ... },
///       "not_before":    1700000000,
///       "not_after":     1731536000
///     }
///   }
/// }
/// ```
fn parse_certstream_message(
    text:         &str,
    variant_map:  &std::collections::HashMap<String, String>,
    source_domain: &str,
) -> Option<CertstreamHit> {
    let j: serde_json::Value = serde_json::from_str(text).ok()?;
    if j.get("message_type")?.as_str()? != "certificate_update" { return None; }
    let leaf = j.get("data")?.get("leaf_cert")?;
    let all_domains: Vec<String> = leaf.get("all_domains")?
        .as_array()?.iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    // Find any SAN that matches a variant (apex + wildcard-stripped).
    let mut matched_variant: Option<(String, String)> = None;
    let mut matched_sans: Vec<String> = Vec::new();
    for san in &all_domains {
        let san_apex = san.trim_start_matches("*.").to_lowercase();
        if let Some(kind) = variant_map.get(&san_apex) {
            matched_sans.push(san.clone());
            matched_variant.get_or_insert_with(|| (san_apex.clone(), kind.clone()));
        }
    }
    let (matched_apex, variant_type) = matched_variant?;

    let subject_cn = leaf.get("subject").and_then(|s| s.get("CN")).and_then(|v| v.as_str())
        .unwrap_or("").to_string();
    let issuer_cn  = leaf.get("issuer").and_then(|s| s.get("CN")).and_then(|v| v.as_str())
        .unwrap_or("").to_string();
    let not_before = leaf.get("not_before").and_then(|v| v.as_i64())
        .map(|ts| chrono::DateTime::from_timestamp(ts, 0)
            .map(|d| d.to_rfc3339()).unwrap_or_default());
    let log_url = j.get("data").and_then(|d| d.get("cert_link"))
        .and_then(|v| v.as_str()).map(|s| s.to_string());

    Some(CertstreamHit {
        source_domain:   source_domain.to_string(),
        matched:         matched_apex,
        variant_type,
        cert_subject:    subject_cn,
        cert_san:        matched_sans,
        issuer:          issuer_cn,
        not_before,
        log_url,
        seen_at:         chrono::Utc::now().to_rfc3339(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_msg(domains: &[&str]) -> String {
        let arr: Vec<serde_json::Value> = domains.iter().map(|s| serde_json::json!(s)).collect();
        serde_json::json!({
            "message_type": "certificate_update",
            "data": {
                "cert_link":  "https://example.test/cert/123",
                "leaf_cert": {
                    "all_domains":  arr,
                    "subject":      { "CN": domains[0] },
                    "issuer":       { "CN": "Let's Encrypt" },
                    "not_before":   1735689600i64,
                    "not_after":    1737000000i64,
                }
            }
        }).to_string()
    }

    #[test]
    fn matches_an_exact_lookalike() {
        let mut map = std::collections::HashMap::new();
        map.insert("cybrium-pay.ai".to_string(), "brand-suffix".to_string());
        let msg = fake_msg(&["www.cybrium-pay.ai", "cybrium-pay.ai"]);
        let hit = parse_certstream_message(&msg, &map, "cybrium.ai").unwrap();
        assert_eq!(hit.matched, "cybrium-pay.ai");
        assert_eq!(hit.variant_type, "brand-suffix");
        assert!(hit.cert_san.iter().any(|s| s == "cybrium-pay.ai"));
    }

    #[test]
    fn ignores_non_match() {
        let map = std::collections::HashMap::new();
        let msg = fake_msg(&["totally-unrelated.example"]);
        assert!(parse_certstream_message(&msg, &map, "cybrium.ai").is_none());
    }

    #[test]
    fn ignores_heartbeats() {
        let beat = serde_json::json!({"message_type":"heartbeat"}).to_string();
        let map = std::collections::HashMap::new();
        assert!(parse_certstream_message(&beat, &map, "cybrium.ai").is_none());
    }

    #[test]
    fn strips_wildcard() {
        let mut map = std::collections::HashMap::new();
        map.insert("cybriumxyz.com".to_string(), "typo".to_string());
        let msg = fake_msg(&["*.cybriumxyz.com"]);
        let hit = parse_certstream_message(&msg, &map, "cybrium.ai").unwrap();
        assert_eq!(hit.matched, "cybriumxyz.com");
    }
}
