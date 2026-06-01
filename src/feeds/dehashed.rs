//! DeHashed feed client.
//!
//! API: https://api.dehashed.com/search?query=domain:<X>
//! Auth: HTTP Basic with `<email>:<api_key>`. The env var format we
//! accept is `email:apikey` so the operator sets one secret.
//! Docs: https://www.dehashed.com/docs

use super::{cache_path, client_for, read_cache, write_cache, FeedOpts, FeedRecord, FeedResult};

pub async fn query(domain: &str, key: &str, opts: &FeedOpts) -> FeedResult {
    // Cache key uses the domain — same query every time.
    let cpath = cache_path("dehashed", domain);
    if let Some(cached) = read_cache(&cpath, opts.cache_ttl) {
        return cached;
    }

    let (email, api_key) = match key.split_once(':') {
        Some((e, k)) if !e.is_empty() && !k.is_empty() => (e, k),
        _ => return FeedResult::failed("dehashed",
            "DEHASHED_API_KEY must be in 'email:apikey' format"),
    };

    let client = match client_for(opts.http_timeout) {
        Ok(c) => c,
        Err(e) => return FeedResult::failed("dehashed", format!("client build: {e}")),
    };

    let url = format!("https://api.dehashed.com/search?query=domain:{domain}");
    let resp = client.get(&url)
        .basic_auth(email, Some(api_key))
        .header("Accept", "application/json")
        .send().await;

    let body: serde_json::Value = match resp {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or(serde_json::Value::Null),
        Ok(r)  => return FeedResult::failed("dehashed", format!("HTTP {}", r.status())),
        Err(e) => return FeedResult::failed("dehashed", format!("request: {e}")),
    };

    let mut records = Vec::new();
    if let Some(entries) = body.get("entries").and_then(|v| v.as_array()) {
        for e in entries.iter().take(opts.max_records) {
            let email_val = e.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let db        = e.get("database_name").and_then(|v| v.as_str()).map(String::from);
            // DeHashed sometimes returns timestamp under "obtained_from" or similar;
            // we record the database name as the breach_label and leave
            // exposed_at as None unless an obvious field is present.
            let when = e.get("obtained_at").and_then(|v| v.as_str())
                .or_else(|| e.get("date").and_then(|v| v.as_str()))
                .map(String::from);

            // Severity: presence of password or hashed_password = high,
            // bare email = info.
            let has_pw = e.get("password").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
                || e.get("hashed_password").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
            let severity = if has_pw { "high" } else { "info" };

            records.push(FeedRecord {
                source:       "dehashed".into(),
                record_type:  "email".into(),
                value:        email_val,
                breach_label: db,
                exposed_at:   when,
                severity:     severity.into(),
            });
        }
    }

    let r = FeedResult {
        feed: "dehashed".into(),
        queried: true,
        from_cache: false,
        record_count: records.len(),
        records,
        error: None,
    };
    write_cache(&cpath, &r);
    r
}
