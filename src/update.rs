//! `cymail update` — refresh threat-intel caches (DNSBL feeds,
//! lookalike DB), distinct from `cymail upgrade` (binary self-update).
//!
//! Today this is a no-op stub that exists to:
//!   1. Establish the cache directory layout under
//!      $XDG_CACHE_HOME/cymail or ~/.cache/cymail.
//!   2. Surface "no cached feeds, using built-in defaults" honestly
//!      in the platform UI so operators don't think the silence is
//!      a stuck CLI.
//!
//! Real DNSBL CIDR-list mirroring + lookalike-DB pulls land in v0.6
//! when we have a clean answer for the licensing constraints on the
//! large lists (Spamhaus DBL CSV is not redistributable).

use std::path::PathBuf;

pub struct UpdateReport {
    pub cache_dir:        PathBuf,
    pub feeds_refreshed:  Vec<String>,
    pub feeds_skipped:    Vec<String>,
    pub bytes_written:    u64,
}

pub fn update() -> Result<UpdateReport, std::io::Error> {
    let cache = cache_dir();
    std::fs::create_dir_all(&cache)?;

    let mut report = UpdateReport {
        cache_dir:       cache.clone(),
        feeds_refreshed: Vec::new(),
        feeds_skipped:   Vec::new(),
        bytes_written:   0,
    };

    // Stub: write a marker so the cache dir exists + we have a
    // timestamp the next `cymail update` can compare against.
    let marker = cache.join("last_update");
    let now = chrono::Utc::now().to_rfc3339();
    std::fs::write(&marker, now.as_bytes())?;
    report.bytes_written += now.len() as u64;
    report.feeds_refreshed.push("internal:last_update_marker".to_string());

    // Document the in-built feeds (no mirror yet — runtime DNS lookups
    // are the source of truth for v0.5).
    for f in ["spamhaus-dbl", "spamhaus-zen", "surbl", "uribl", "barracuda-brbl", "dnswl"] {
        report.feeds_skipped.push(format!("{f}: live DNS only (cache n/a in v0.5)"));
    }

    Ok(report)
}

pub fn cache_dir() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_CACHE_HOME") {
        return PathBuf::from(x).join("cymail");
    }
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h).join(".cache").join("cymail");
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(la) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(la).join("cymail").join("cache");
        }
    }
    std::env::temp_dir().join("cymail-cache")
}
