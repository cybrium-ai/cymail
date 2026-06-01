//! Commercial breach-feed integrations (Sprint 98 P3 — v0.6.2).
//!
//! Each feed:
//!   - Skipped entirely when its env var is absent.
//!   - Rate-limited to the provider's published soft limit.
//!   - Caches results for 24h under $XDG_CACHE_HOME/cymail/feeds/
//!     so repeated runs don't re-spend the API budget.
//!   - Surfaces structured records into LeakReport.commercial_feeds.
//!
//! `cymail leak` calls run_all() with the operator-supplied opts;
//! providers with no key never reach the network.

pub mod dehashed;
pub mod intelx;
pub mod snusbase;

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// One record exposed by a feed. Stable shape so the platform's
/// finding translator can map it uniformly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedRecord {
    pub source:       String,      // feed name
    pub record_type:  String,      // "email" / "hash" / "password" / "ip" / etc.
    pub value:        String,      // the exposed value (email address etc.)
    pub breach_label: Option<String>,    // which breach (db_name / source / etc.)
    pub exposed_at:   Option<String>,    // when, if reported
    pub severity:     String,            // "info" / "medium" / "high"
}

/// Result of one feed query. Wraps records + status so callers can
/// distinguish "no key, skipped" from "key but zero hits".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedResult {
    pub feed:        String,
    pub queried:     bool,
    pub from_cache:  bool,
    pub record_count: usize,
    pub records:     Vec<FeedRecord>,
    pub error:       Option<String>,
}

impl FeedResult {
    pub fn skipped(feed: &str, reason: &str) -> Self {
        Self {
            feed: feed.to_string(), queried: false, from_cache: false,
            record_count: 0, records: Vec::new(),
            error: Some(format!("skipped: {reason}")),
        }
    }
    pub fn failed(feed: &str, e: impl std::fmt::Display) -> Self {
        Self {
            feed: feed.to_string(), queried: true, from_cache: false,
            record_count: 0, records: Vec::new(),
            error: Some(e.to_string()),
        }
    }
}

pub struct FeedOpts {
    pub http_timeout:    Duration,
    pub cache_ttl:       Duration,
    pub max_records:     usize,
    pub dehashed_key:    Option<String>,
    pub intelx_key:      Option<String>,
    pub snusbase_key:    Option<String>,
}

impl Default for FeedOpts {
    fn default() -> Self {
        Self {
            http_timeout: Duration::from_secs(30),
            cache_ttl:    Duration::from_secs(60 * 60 * 24),    // 24h
            max_records:  500,
            dehashed_key: std::env::var("DEHASHED_API_KEY").ok(),
            intelx_key:   std::env::var("INTELX_API_KEY").ok(),
            snusbase_key: std::env::var("SNUSBASE_API_KEY").ok(),
        }
    }
}

/// Top-level orchestrator. Calls every configured feed and returns
/// the per-feed results.
pub async fn run_all(domain: &str, opts: &FeedOpts) -> Vec<FeedResult> {
    let mut out = Vec::new();
    out.push(match &opts.dehashed_key {
        Some(key) => dehashed::query(domain, key, opts).await,
        None      => FeedResult::skipped("dehashed", "DEHASHED_API_KEY absent"),
    });
    out.push(match &opts.intelx_key {
        Some(key) => intelx::query(domain, key, opts).await,
        None      => FeedResult::skipped("intelx", "INTELX_API_KEY absent"),
    });
    out.push(match &opts.snusbase_key {
        Some(key) => snusbase::query(domain, key, opts).await,
        None      => FeedResult::skipped("snusbase", "SNUSBASE_API_KEY absent"),
    });
    out
}

// ─── HTTP client helper ───────────────────────────────────────────
pub(crate) fn client_for(timeout: Duration) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(format!("cymail/{}", env!("CARGO_PKG_VERSION")))
        .build()
}

// ─── 24h disk cache ───────────────────────────────────────────────
//
// Cache key = sha256(feed_name + ":" + query). Cache value = full
// FeedResult JSON. On read, we honour the file mtime against the TTL.

pub(crate) fn cache_path(feed: &str, query: &str) -> PathBuf {
    let key = cache_key(feed, query);
    cache_dir().join(format!("{key}.json"))
}

fn cache_key(feed: &str, query: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(feed.as_bytes());
    h.update(b":");
    h.update(query.as_bytes());
    let bytes = h.finalize();
    let hex_chars = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(hex_chars[(b >> 4) as usize] as char);
        s.push(hex_chars[(b & 0x0f) as usize] as char);
    }
    s
}

fn cache_dir() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_CACHE_HOME") {
        return PathBuf::from(x).join("cymail").join("feeds");
    }
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h).join(".cache").join("cymail").join("feeds");
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(la) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(la).join("cymail").join("cache").join("feeds");
        }
    }
    std::env::temp_dir().join("cymail-feeds")
}

/// Read cached FeedResult if present and within ttl, else None.
pub(crate) fn read_cache(path: &Path, ttl: Duration) -> Option<FeedResult> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let age = std::time::SystemTime::now().duration_since(modified).ok()?;
    if age > ttl { return None; }
    let body = std::fs::read(path).ok()?;
    let mut fr: FeedResult = serde_json::from_slice(&body).ok()?;
    fr.from_cache = true;
    Some(fr)
}

/// Write a FeedResult to disk. Best effort — never fails the query
/// on cache write error.
pub(crate) fn write_cache(path: &Path, result: &FeedResult) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(s) = serde_json::to_vec(result) {
        let _ = std::fs::write(path, s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_deterministic() {
        let a = cache_key("dehashed", "cybrium.ai");
        let b = cache_key("dehashed", "cybrium.ai");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);    // sha256 hex
    }

    #[test]
    fn cache_key_distinguishes_feed() {
        let a = cache_key("dehashed", "cybrium.ai");
        let b = cache_key("intelx",   "cybrium.ai");
        assert_ne!(a, b);
    }

    #[test]
    fn skipped_result_has_skip_error() {
        let r = FeedResult::skipped("dehashed", "no key");
        assert!(!r.queried);
        assert!(r.error.as_deref().unwrap().contains("skipped"));
    }
}
