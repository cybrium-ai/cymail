//! SnusBase feed client.
//!
//! POST https://api.snusbase.com/data/search
//! Header: `auth: <api_key>`
//! Body:   `{ terms: ["<domain>"], types: ["email"], wildcard: true }`
//!
//! Docs: https://snusbase.com/api

use super::{cache_path, client_for, read_cache, write_cache, FeedOpts, FeedRecord, FeedResult};

pub async fn query(domain: &str, key: &str, opts: &FeedOpts) -> FeedResult {
    let cpath = cache_path("snusbase", domain);
    if let Some(cached) = read_cache(&cpath, opts.cache_ttl) {
        return cached;
    }

    let client = match client_for(opts.http_timeout) {
        Ok(c) => c,
        Err(e) => return FeedResult::failed("snusbase", format!("client build: {e}")),
    };

    let body = serde_json::json!({
        "terms":    [format!("@{domain}")],
        "types":    ["email"],
        "wildcard": true,
    });

    let resp = client.post("https://api.snusbase.com/data/search")
        .header("auth", key)
        .header("Content-Type", "application/json")
        .json(&body)
        .send().await;

    let body: serde_json::Value = match resp {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or(serde_json::Value::Null),
        Ok(r)  => return FeedResult::failed("snusbase", format!("HTTP {}", r.status())),
        Err(e) => return FeedResult::failed("snusbase", format!("request: {e}")),
    };

    let mut records = Vec::new();
    // SnusBase returns { results: { "<source_name>": [ {email, password, hash, salt}, ... ], ... } }
    if let Some(sources) = body.get("results").and_then(|v| v.as_object()) {
        for (source_name, entries) in sources {
            if let Some(arr) = entries.as_array() {
                for entry in arr.iter().take(opts.max_records.saturating_sub(records.len())) {
                    let email = entry.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let has_pw = entry.get("password").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
                        || entry.get("hash").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
                    records.push(FeedRecord {
                        source:       "snusbase".into(),
                        record_type:  "email".into(),
                        value:        email,
                        breach_label: Some(source_name.clone()),
                        exposed_at:   None,
                        severity:     if has_pw { "high".into() } else { "info".into() },
                    });
                    if records.len() >= opts.max_records { break; }
                }
            }
            if records.len() >= opts.max_records { break; }
        }
    }

    let r = FeedResult {
        feed: "snusbase".into(),
        queried: true,
        from_cache: false,
        record_count: records.len(),
        records,
        error: None,
    };
    write_cache(&cpath, &r);
    r
}
