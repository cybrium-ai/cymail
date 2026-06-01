//! Intelligence X feed client.
//!
//! Two-step API:
//!   1. POST /intelligent/search  → returns search ID
//!   2. POST /intelligent/search/result?id=<id>  → poll until ready
//!
//! Auth: `x-key` header.
//! Docs: https://intelx.io/api

use std::time::Duration;

use super::{cache_path, client_for, read_cache, write_cache, FeedOpts, FeedRecord, FeedResult};

const BASE: &str = "https://2.intelx.io";

pub async fn query(domain: &str, key: &str, opts: &FeedOpts) -> FeedResult {
    let cpath = cache_path("intelx", domain);
    if let Some(cached) = read_cache(&cpath, opts.cache_ttl) {
        return cached;
    }

    let client = match client_for(opts.http_timeout) {
        Ok(c) => c,
        Err(e) => return FeedResult::failed("intelx", format!("client build: {e}")),
    };

    // ── 1. Initiate search ────────────────────────────────────────
    let search_body = serde_json::json!({
        "term":        domain,
        "buckets":     [],
        "lookuplevel": 0,
        "maxresults":  opts.max_records,
        "timeout":     0,
        "datefrom":    "",
        "dateto":      "",
        "sort":        4,         // newest first
        "media":       0,
        "terminate":   [],
        "target":      0,         // 0 = stats + records (full search)
    });

    let init = client.post(format!("{BASE}/intelligent/search"))
        .header("x-key", key)
        .json(&search_body)
        .send().await;

    let id = match init {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
            match body.get("id").and_then(|v| v.as_str()) {
                Some(id) => id.to_string(),
                None => return FeedResult::failed("intelx", "no search id returned"),
            }
        }
        Ok(r)  => return FeedResult::failed("intelx", format!("init HTTP {}", r.status())),
        Err(e) => return FeedResult::failed("intelx", format!("init request: {e}")),
    };

    // ── 2. Poll for results (status code in body, not HTTP code) ──
    let mut records: Vec<FeedRecord> = Vec::new();
    for _attempt in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let poll = client.get(format!("{BASE}/intelligent/search/result?id={id}&limit={}", opts.max_records))
            .header("x-key", key)
            .send().await;
        let body: serde_json::Value = match poll {
            Ok(r) if r.status().is_success() => r.json().await.unwrap_or(serde_json::Value::Null),
            Ok(r)  => return FeedResult::failed("intelx", format!("poll HTTP {}", r.status())),
            Err(e) => return FeedResult::failed("intelx", format!("poll request: {e}")),
        };
        // status field: 0 = success, 1 = no_more_results, 2 = search_id_not_found, 3 = no_results
        let status = body.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
        if let Some(items) = body.get("records").and_then(|v| v.as_array()) {
            for item in items {
                let bucket = item.get("bucket").and_then(|v| v.as_str()).map(String::from);
                let when   = item.get("date").and_then(|v| v.as_str()).map(String::from);
                let value  = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                records.push(FeedRecord {
                    source:       "intelx".into(),
                    record_type:  "intel-record".into(),
                    value,
                    breach_label: bucket,
                    exposed_at:   when,
                    severity:     "medium".into(),
                });
                if records.len() >= opts.max_records { break; }
            }
        }
        if status == 1 || status == 3 || records.len() >= opts.max_records {
            break;
        }
    }

    let r = FeedResult {
        feed: "intelx".into(),
        queried: true,
        from_cache: false,
        record_count: records.len(),
        records,
        error: None,
    };
    write_cache(&cpath, &r);
    r
}
