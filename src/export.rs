//! Multi-format exporters (P4 — v0.5).
//!
//! Every cymail report type can be rendered as:
//!   - json   — pretty-printed serde JSON (existing default)
//!   - sarif  — SARIF 2.1.0 minimal (one run, one tool, n results).
//!              The platform's findings ingest pipeline already eats
//!              SARIF from cyscan, so cymail findings drop in clean.
//!   - csv    — flat csv suitable for spreadsheet pivot
//!   - html   — standalone HTML page (no external assets, no JS),
//!              Cybrium-themed, prints cleanly to PDF
//!
//! The four supported report types: EmailReport (scan),
//! DiscoveryReport, ReputationReport, LeakReport. Each gets its own
//! to_csv() / to_html() / to_sarif() implementation; JSON is
//! universal via serde.

use serde::Serialize;

use crate::{EmailReport, discover::DiscoveryReport, reputation::ReputationReport, leak::LeakReport};

/// Render any serde-Serializable value as pretty JSON.
pub fn to_json<T: Serialize>(v: &T) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into())
}

// ─── SARIF 2.1.0 ───────────────────────────────────────────────────
//
// Minimal valid SARIF. The platform's existing SARIF reader will
// happily ingest this; one `results` entry per finding/leak/etc.

pub fn email_report_to_sarif(r: &EmailReport) -> String {
    let results: Vec<serde_json::Value> = r.findings.iter().map(|f| {
        serde_json::json!({
            "ruleId":      f.id,
            "level":       sarif_level(&f.severity),
            "message":     { "text": f.description },
            "locations":   [{
                "physicalLocation": {
                    "artifactLocation": { "uri": format!("dns://{}", r.domain) }
                }
            }],
            "properties":  { "title": f.title, "severity": f.severity, "domain": r.domain }
        })
    }).collect();
    sarif_envelope("cymail-scan", &results)
}

pub fn discovery_to_sarif(r: &DiscoveryReport) -> String {
    let results: Vec<serde_json::Value> = r.emails.iter().map(|e| {
        let mut level = "note";
        let mut tags: Vec<&str> = Vec::new();
        if let Some(rep) = &e.reputation {
            if rep.blacklisted.unwrap_or(false) { level = "error"; tags.push("blacklisted"); }
            if rep.malicious.unwrap_or(false)   { level = "error"; tags.push("malicious"); }
            if rep.credentials_leaked.unwrap_or(false) { level = "warning"; tags.push("credentials-leaked"); }
            if rep.data_breach.unwrap_or(false) { level = "warning"; tags.push("data-breach"); }
        }
        serde_json::json!({
            "ruleId":  "cymail.discovered_email",
            "level":   level,
            "message": { "text": format!("Discovered {} from {}", e.address, e.source) },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": format!("mailto:{}", e.address) }
                }
            }],
            "properties": { "source": e.source, "validated": e.validated, "domain": r.domain, "tags": tags }
        })
    }).collect();
    sarif_envelope("cymail-discover", &results)
}

pub fn reputation_to_sarif(r: &ReputationReport) -> String {
    let mut results: Vec<serde_json::Value> = Vec::new();
    for hit in r.dnsbl.queries.iter().filter(|h| h.listed && h.kind == "blacklist") {
        results.push(serde_json::json!({
            "ruleId":  "cymail.dnsbl_listed",
            "level":   "error",
            "message": { "text": format!("{} listed on {} ({})", hit.target, hit.list, hit.return_codes.join(",")) },
            "properties": { "list": hit.list, "target": hit.target, "domain": r.domain }
        }));
    }
    if r.spf_lookups.over_limit {
        results.push(serde_json::json!({
            "ruleId":  "cymail.spf_lookup_limit",
            "level":   "error",
            "message": { "text": format!("SPF record uses {} DNS lookups, RFC 7208 §4.6.4 cap is 10", r.spf_lookups.lookup_count) },
            "properties": { "lookup_count": r.spf_lookups.lookup_count, "domain": r.domain }
        }));
    }
    for k in r.dkim_hygiene.iter().filter(|k| k.hygiene != "ok") {
        results.push(serde_json::json!({
            "ruleId":  "cymail.dkim_weak_key",
            "level":   if k.hygiene == "weak" { "warning" } else { "error" },
            "message": { "text": k.issue.clone().unwrap_or_else(|| format!("Selector {} key hygiene: {}", k.selector, k.hygiene)) },
            "properties": { "selector": k.selector, "key_bits": k.key_bits, "domain": r.domain }
        }));
    }
    if !r.dnssec.signed {
        results.push(serde_json::json!({
            "ruleId":  "cymail.dnssec_unsigned",
            "level":   "warning",
            "message": { "text": "Domain is not DNSSEC-signed" },
            "properties": { "domain": r.domain }
        }));
    }
    sarif_envelope("cymail-reputation", &results)
}

pub fn leak_to_sarif(r: &LeakReport) -> String {
    let mut results: Vec<serde_json::Value> = Vec::new();
    for b in &r.breaches {
        results.push(serde_json::json!({
            "ruleId":  "cymail.breach_appearance",
            "level":   "error",
            "message": { "text": format!("{} appears in breach: {} ({})", r.domain, b.title, b.breach_date.clone().unwrap_or_default()) },
            "properties": { "breach": b.name, "data_classes": b.data_classes, "pwn_count": b.pwn_count, "domain": r.domain }
        }));
    }
    for h in &r.github_leaks {
        results.push(serde_json::json!({
            "ruleId":  "cymail.github_code_hit",
            "level":   "warning",
            "message": { "text": format!("Domain appears near secret-shaped neighbours in {}/{}", h.repo, h.path) },
            "locations": [{ "physicalLocation": { "artifactLocation": { "uri": h.html_url } } }],
            "properties": { "repo": h.repo, "path": h.path, "domain": r.domain }
        }));
    }
    for la in r.lookalike_domains.iter().filter(|l| l.cert_issued) {
        results.push(serde_json::json!({
            "ruleId":  "cymail.lookalike_domain",
            "level":   "error",
            "message": { "text": format!("Lookalike domain {} has a cert ({}) — likely impersonation", la.variant, la.recent_cert_at.clone().unwrap_or_default()) },
            "properties": { "variant": la.variant, "variant_type": la.variant_type, "recent_cert_at": la.recent_cert_at, "source_domain": r.domain }
        }));
    }
    sarif_envelope("cymail-leak", &results)
}

fn sarif_level(sev: &str) -> &'static str {
    match sev.to_lowercase().as_str() {
        "critical" | "high"  => "error",
        "medium" | "warning" => "warning",
        "low" | "info"       => "note",
        _                    => "none",
    }
}

fn sarif_envelope(tool_subname: &str, results: &[serde_json::Value]) -> String {
    let v = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":      "cymail",
                    "fullName":  format!("cymail/{tool_subname}"),
                    "version":   env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/cybrium-ai/cymail",
                }
            },
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

// ─── CSV ───────────────────────────────────────────────────────────
//
// Minimal handcrafted CSV (no csv-rs dep). We only need to escape
// double-quotes + commas + newlines via "..." wrapping.
fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn email_report_to_csv(r: &EmailReport) -> String {
    let mut out = String::from("domain,score,grade,finding_id,severity,title,description\n");
    for f in &r.findings {
        out.push_str(&format!("{},{},{},{},{},{},{}\n",
            csv_field(&r.domain),
            r.score, csv_field(&r.grade),
            csv_field(&f.id), csv_field(&f.severity),
            csv_field(&f.title), csv_field(&f.description)));
    }
    if r.findings.is_empty() {
        out.push_str(&format!("{},{},{},,,,\n", csv_field(&r.domain), r.score, csv_field(&r.grade)));
    }
    out
}

pub fn discovery_to_csv(r: &DiscoveryReport) -> String {
    let mut out = String::from("domain,address,source,validated,blacklisted,malicious,credentials_leaked,data_breach\n");
    for e in &r.emails {
        let rep = e.reputation.as_ref();
        out.push_str(&format!("{},{},{},{},{},{},{},{}\n",
            csv_field(&r.domain),
            csv_field(&e.address),
            csv_field(&e.source),
            e.validated.map(|b| b.to_string()).unwrap_or_default(),
            rep.and_then(|x| x.blacklisted).map(|b| b.to_string()).unwrap_or_default(),
            rep.and_then(|x| x.malicious).map(|b| b.to_string()).unwrap_or_default(),
            rep.and_then(|x| x.credentials_leaked).map(|b| b.to_string()).unwrap_or_default(),
            rep.and_then(|x| x.data_breach).map(|b| b.to_string()).unwrap_or_default(),
        ));
    }
    out
}

pub fn reputation_to_csv(r: &ReputationReport) -> String {
    let mut out = String::from("category,key,value\n");
    out.push_str(&format!("provider,vendor,{}\n", csv_field(&r.provider.vendor)));
    out.push_str(&format!("provider,category,{}\n", csv_field(&r.provider.category)));
    out.push_str(&format!("dnssec,signed,{}\n", r.dnssec.signed));
    out.push_str(&format!("bimi,configured,{}\n", r.bimi.configured));
    out.push_str(&format!("spf,lookup_count,{}\n", r.spf_lookups.lookup_count));
    out.push_str(&format!("spf,over_limit,{}\n", r.spf_lookups.over_limit));
    for hit in r.dnsbl.queries.iter().filter(|h| h.listed) {
        out.push_str(&format!("dnsbl,{},{}\n", csv_field(&hit.list), csv_field(&hit.target)));
    }
    for k in &r.dkim_hygiene {
        out.push_str(&format!("dkim,{},{}/{}\n",
            csv_field(&k.selector), k.hygiene,
            k.key_bits.map(|n| n.to_string()).unwrap_or_default()));
    }
    out
}

pub fn leak_to_csv(r: &LeakReport) -> String {
    let mut out = String::from("category,key,value,extra\n");
    for b in &r.breaches {
        out.push_str(&format!("breach,{},{},{}\n",
            csv_field(&b.name), csv_field(&b.title),
            csv_field(&b.data_classes.join(";"))));
    }
    for h in &r.github_leaks {
        out.push_str(&format!("github,{},{},{}\n",
            csv_field(&h.repo), csv_field(&h.path), csv_field(&h.html_url)));
    }
    for la in r.lookalike_domains.iter().filter(|l| l.cert_issued) {
        out.push_str(&format!("lookalike,{},{},{}\n",
            csv_field(&la.variant), csv_field(&la.variant_type),
            csv_field(&la.recent_cert_at.clone().unwrap_or_default())));
    }
    out
}

// ─── HTML ──────────────────────────────────────────────────────────
//
// One-page, self-contained, Cybrium-themed report. Prints cleanly.
const HTML_HEAD: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<title>cymail report — Cybrium AI</title>
<style>
  :root {
    --bg:#0a0a0f; --bg2:#15151c; --fg:#e8e8f0; --dim:#8b8b9e;
    --accent:#a855f7; --ok:#22c55e; --warn:#facc15; --err:#ef4444;
    --border: #2a2a35;
  }
  body { background:var(--bg); color:var(--fg); font:14px/1.6 ui-sans-serif,system-ui,sans-serif; margin:0; padding:32px; }
  h1 { color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:8px; }
  h2 { color:var(--fg); margin-top:36px; }
  h3 { color:var(--dim); font-weight:500; font-size:13px; text-transform:uppercase; letter-spacing:0.05em; }
  .card { background:var(--bg2); border:1px solid var(--border); border-radius:8px; padding:20px; margin-bottom:16px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; }
  .stat { background:var(--bg2); border:1px solid var(--border); border-radius:8px; padding:16px; }
  .stat-value { font-size:24px; font-weight:600; color:var(--fg); }
  .stat-label { color:var(--dim); font-size:12px; text-transform:uppercase; margin-top:4px; }
  table { border-collapse:collapse; width:100%; margin:8px 0; font-size:13px; }
  th,td { border-bottom:1px solid var(--border); padding:8px 12px; text-align:left; }
  th { color:var(--dim); font-weight:500; font-size:11px; text-transform:uppercase; }
  .ok { color:var(--ok); } .warn { color:var(--warn); } .err { color:var(--err); }
  .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; border:1px solid; }
  .badge.ok { color:var(--ok); border-color:var(--ok); }
  .badge.warn { color:var(--warn); border-color:var(--warn); }
  .badge.err { color:var(--err); border-color:var(--err); }
  footer { margin-top:48px; padding-top:16px; border-top:1px solid var(--border); color:var(--dim); font-size:12px; }
  a { color:var(--accent); }
  @media print { body { background:white; color:black; } .card,.stat { background:white; border-color:#ccc; } }
</style>
</head><body>"##;

const HTML_FOOT: &str = r##"<footer>Generated by <a href="https://github.com/cybrium-ai/cymail">cymail</a> — Cybrium AI · Email Posture &amp; Reputation Scanner</footer></body></html>"##;

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

// ─── HTML body fragments (no <html>/<head>/<body> wrapper) ────────
//
// Used by the embedded web UI in server.rs which provides its own
// chrome (real Cybrium shield + wordmark, sticky export pills,
// platform-matched dark tokens). The `*_to_html()` functions below
// keep the full standalone wrapper for CLI `--format html`.

pub fn email_report_to_html_body(r: &EmailReport) -> String {
    let mut h = String::new();
    h.push_str(&format!("<div class='card'><h2>Posture · {}</h2>", html_esc(&r.domain)));
    h.push_str(&format!("<div class='grid'>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Score / 100</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Grade</div></div>\
        <div class='stat'><div class='stat-value'>{}/{}/{}</div><div class='stat-label'>SPF · DKIM · DMARC</div></div>\
    </div></div>",
        r.score, html_esc(&r.grade),
        if r.spf.configured { "✓" } else { "✗" },
        if r.dkim.configured { "✓" } else { "✗" },
        if r.dmarc.configured { "✓" } else { "✗" }));
    h.push_str("<div class='card'><h2>Findings</h2>");
    if r.findings.is_empty() {
        h.push_str("<p class='card-hint ok'>No findings.</p>");
    } else {
        h.push_str("<table><tr><th>Severity</th><th>ID</th><th>Title</th><th>Description</th></tr>");
        for f in &r.findings {
            let cls = match f.severity.as_str() {
                "critical" => "crit", "high" => "err", "medium" => "warn", _ => "ok",
            };
            h.push_str(&format!(
                "<tr><td><span class='badge {cls}'>{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_esc(&f.severity), html_esc(&f.id), html_esc(&f.title), html_esc(&f.description)));
        }
        h.push_str("</table>");
    }
    h.push_str(&format!("<p class='card-hint'>Scanned at {}</p></div>", html_esc(&r.scanned_at)));
    h
}

pub fn discovery_to_html_body(r: &DiscoveryReport) -> String {
    let mut h = String::new();
    h.push_str(&format!("<div class='card'><h2>Discovery · {}</h2>", html_esc(&r.domain)));
    h.push_str(&format!("<div class='grid'>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Addresses</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>MX hosts</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Catch-all</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Sources</div></div>\
    </div></div>",
        r.emails.len(), r.mx_hosts.len(),
        match r.catch_all { Some(true) => "yes", Some(false) => "no", None => "—" },
        r.sources_queried.len()));
    h.push_str("<div class='card'><h2>Discovered emails</h2>");
    h.push_str("<table><tr><th>Address</th><th>Source</th><th>Validated</th><th>Flags</th></tr>");
    for e in &r.emails {
        let v = match e.validated {
            Some(true) => "<span class='ok'>✓</span>",
            Some(false) => "<span class='err'>✗</span>",
            None => "<span class='card-hint'>—</span>",
        };
        let flags = e.reputation.as_ref().map(|x| {
            let mut b = String::new();
            if x.blacklisted.unwrap_or(false)         { b.push_str("<span class='badge err'>blacklisted</span> "); }
            if x.malicious.unwrap_or(false)           { b.push_str("<span class='badge err'>malicious</span> "); }
            if x.credentials_leaked.unwrap_or(false)  { b.push_str("<span class='badge warn'>creds-leaked</span> "); }
            if x.data_breach.unwrap_or(false)         { b.push_str("<span class='badge warn'>in-breach</span> "); }
            b
        }).unwrap_or_default();
        h.push_str(&format!("<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_esc(&e.address), html_esc(&e.source), v, flags));
    }
    h.push_str("</table></div>");
    h
}

pub fn reputation_to_html_body(r: &ReputationReport) -> String {
    let mut h = String::new();
    h.push_str(&format!("<div class='card'><h2>Reputation · {}</h2>", html_esc(&r.domain)));
    h.push_str(&format!("<div class='grid'>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Provider</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>DNSSEC</div></div>\
        <div class='stat'><div class='stat-value'>{}/{}</div><div class='stat-label'>SPF lookups</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>DNSBL listings</div></div>\
    </div></div>",
        html_esc(&r.provider.vendor),
        if r.dnssec.signed { "signed" } else { "unsigned" },
        r.spf_lookups.lookup_count, r.spf_lookups.limit,
        r.dnsbl.blacklisted_listings));

    h.push_str("<div class='card'><h2>DNSBL queries</h2><table><tr><th>List</th><th>Kind</th><th>Target</th><th>Listed</th></tr>");
    for hit in &r.dnsbl.queries {
        let cls = if hit.listed && hit.kind == "blacklist" { "err" } else if hit.listed { "ok" } else { "" };
        h.push_str(&format!("<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td class='{cls}'>{}</td></tr>",
            html_esc(&hit.list), html_esc(&hit.kind), html_esc(&hit.target),
            if hit.listed { "yes" } else { "no" }));
    }
    h.push_str("</table></div>");

    h.push_str("<div class='card'><h2>DKIM keys</h2><table><tr><th>Selector</th><th>Algorithm</th><th>Bits</th><th>Hygiene</th><th>Note</th></tr>");
    for k in &r.dkim_hygiene {
        let cls = match k.hygiene.as_str() { "ok" => "ok", "weak" => "warn", _ => "err" };
        h.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td class='{cls}'>{}</td><td>{}</td></tr>",
            html_esc(&k.selector), html_esc(&k.algorithm.clone().unwrap_or_default()),
            k.key_bits.map(|n| n.to_string()).unwrap_or_default(),
            html_esc(&k.hygiene), html_esc(&k.issue.clone().unwrap_or_default())));
    }
    h.push_str("</table></div>");
    h
}

pub fn leak_to_html_body(r: &LeakReport) -> String {
    let mut h = String::new();
    h.push_str(&format!("<div class='card'><h2>Leak telemetry · {}</h2>", html_esc(&r.domain)));
    h.push_str(&format!("<div class='grid'>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Breaches</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>GitHub hits</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Lookalikes w/ certs</div></div>\
    </div></div>",
        r.breaches.len(), r.github_leaks.len(),
        r.lookalike_domains.iter().filter(|l| l.cert_issued).count()));

    h.push_str("<div class='card'><h2>Breaches (HIBP)</h2>");
    if r.breaches.is_empty() { h.push_str("<p class='card-hint ok'>None.</p>"); }
    else {
        h.push_str("<table><tr><th>Title</th><th>Date</th><th>Accounts</th><th>Data classes</th></tr>");
        for b in &r.breaches {
            h.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_esc(&b.title), html_esc(&b.breach_date.clone().unwrap_or_default()),
                b.pwn_count.map(|n| n.to_string()).unwrap_or_default(),
                html_esc(&b.data_classes.join(", "))));
        }
        h.push_str("</table>");
    }
    h.push_str("</div>");

    h.push_str("<div class='card'><h2>GitHub code hits</h2>");
    if r.github_leaks.is_empty() { h.push_str("<p class='card-hint ok'>None.</p>"); }
    else {
        h.push_str("<table><tr><th>Repo</th><th>Path</th><th>Link</th></tr>");
        for h2 in &r.github_leaks {
            h.push_str(&format!("<tr><td><code>{}</code></td><td><code>{}</code></td><td><a href='{}' target='_blank' rel='noopener'>open</a></td></tr>",
                html_esc(&h2.repo), html_esc(&h2.path), html_esc(&h2.html_url)));
        }
        h.push_str("</table>");
    }
    h.push_str("</div>");

    h.push_str("<div class='card'><h2>Lookalike domains</h2>");
    let cert: Vec<_> = r.lookalike_domains.iter().filter(|l| l.cert_issued).collect();
    if cert.is_empty() { h.push_str("<p class='card-hint ok'>No cert-bearing variants.</p>"); }
    else {
        h.push_str("<table><tr><th>Variant</th><th>Type</th><th>Cert at</th></tr>");
        for la in cert {
            h.push_str(&format!("<tr><td class='err'><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                html_esc(&la.variant), html_esc(&la.variant_type),
                html_esc(&la.recent_cert_at.clone().unwrap_or_default())));
        }
        h.push_str("</table>");
    }
    h.push_str("</div>");
    h
}

pub fn email_report_to_html(r: &EmailReport) -> String {
    let mut h = String::from(HTML_HEAD);
    h.push_str(&format!("<h1>cymail · scan · {}</h1>", html_esc(&r.domain)));
    h.push_str(&format!("<div class='grid'>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Score / 100</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Grade</div></div>\
        <div class='stat'><div class='stat-value'>{}/{}/{}</div><div class='stat-label'>SPF · DKIM · DMARC</div></div>\
    </div>",
        r.score, html_esc(&r.grade),
        if r.spf.configured { "✓" } else { "✗" },
        if r.dkim.configured { "✓" } else { "✗" },
        if r.dmarc.configured { "✓" } else { "✗" }));
    h.push_str("<h2>Findings</h2>");
    if r.findings.is_empty() {
        h.push_str("<div class='card ok'>No findings.</div>");
    } else {
        h.push_str("<table><tr><th>Severity</th><th>ID</th><th>Title</th><th>Description</th></tr>");
        for f in &r.findings {
            let cls = match f.severity.as_str() { "critical"|"high" => "err", "medium" => "warn", _ => "ok" };
            h.push_str(&format!("<tr><td><span class='badge {cls}'>{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_esc(&f.severity), html_esc(&f.id), html_esc(&f.title), html_esc(&f.description)));
        }
        h.push_str("</table>");
    }
    h.push_str(&format!("<p class='stat-label'>Scanned at {}</p>", html_esc(&r.scanned_at)));
    h.push_str(HTML_FOOT);
    h
}

pub fn discovery_to_html(r: &DiscoveryReport) -> String {
    let mut h = String::from(HTML_HEAD);
    h.push_str(&format!("<h1>cymail · discover · {}</h1>", html_esc(&r.domain)));
    h.push_str(&format!("<div class='grid'>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Addresses</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>MX hosts</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Catch-all</div></div>\
    </div>",
        r.emails.len(), r.mx_hosts.len(),
        match r.catch_all { Some(true) => "yes", Some(false) => "no", None => "—" }));
    h.push_str("<h2>Discovered emails</h2>");
    h.push_str("<table><tr><th>Address</th><th>Source</th><th>Validated</th><th>Flags</th></tr>");
    for e in &r.emails {
        let v = match e.validated { Some(true) => "<span class='ok'>✓</span>", Some(false) => "<span class='err'>✗</span>", None => "—" };
        let flags = e.reputation.as_ref().map(|x| {
            let mut b = String::new();
            if x.blacklisted.unwrap_or(false)         { b.push_str("<span class='badge err'>blacklisted</span> "); }
            if x.malicious.unwrap_or(false)           { b.push_str("<span class='badge err'>malicious</span> "); }
            if x.credentials_leaked.unwrap_or(false)  { b.push_str("<span class='badge warn'>creds-leaked</span> "); }
            if x.data_breach.unwrap_or(false)         { b.push_str("<span class='badge warn'>in-breach</span> "); }
            b
        }).unwrap_or_default();
        h.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_esc(&e.address), html_esc(&e.source), v, flags));
    }
    h.push_str("</table>");
    h.push_str(HTML_FOOT);
    h
}

pub fn reputation_to_html(r: &ReputationReport) -> String {
    let mut h = String::from(HTML_HEAD);
    h.push_str(&format!("<h1>cymail · reputation · {}</h1>", html_esc(&r.domain)));
    h.push_str(&format!("<div class='grid'>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Provider</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>DNSSEC</div></div>\
        <div class='stat'><div class='stat-value'>{}/{}</div><div class='stat-label'>SPF lookups</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>DNSBL listings</div></div>\
    </div>",
        html_esc(&r.provider.vendor),
        if r.dnssec.signed { "signed" } else { "unsigned" },
        r.spf_lookups.lookup_count, r.spf_lookups.limit,
        r.dnsbl.blacklisted_listings));

    h.push_str("<h2>DNSBL queries</h2><table><tr><th>List</th><th>Kind</th><th>Target</th><th>Listed</th></tr>");
    for hit in &r.dnsbl.queries {
        let cls = if hit.listed && hit.kind == "blacklist" { "err" } else if hit.listed { "ok" } else { "" };
        h.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td class='{cls}'>{}</td></tr>",
            html_esc(&hit.list), html_esc(&hit.kind), html_esc(&hit.target),
            if hit.listed { "yes" } else { "no" }));
    }
    h.push_str("</table>");

    h.push_str("<h2>DKIM keys</h2><table><tr><th>Selector</th><th>Algorithm</th><th>Bits</th><th>Hygiene</th></tr>");
    for k in &r.dkim_hygiene {
        let cls = match k.hygiene.as_str() { "ok" => "ok", "weak" => "warn", _ => "err" };
        h.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td class='{cls}'>{}</td></tr>",
            html_esc(&k.selector), html_esc(&k.algorithm.clone().unwrap_or_default()),
            k.key_bits.map(|n| n.to_string()).unwrap_or_default(),
            html_esc(&k.hygiene)));
    }
    h.push_str("</table>");
    h.push_str(HTML_FOOT);
    h
}

pub fn leak_to_html(r: &LeakReport) -> String {
    let mut h = String::from(HTML_HEAD);
    h.push_str(&format!("<h1>cymail · leak · {}</h1>", html_esc(&r.domain)));
    h.push_str(&format!("<div class='grid'>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Breaches</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>GitHub hits</div></div>\
        <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Lookalikes w/ certs</div></div>\
    </div>",
        r.breaches.len(), r.github_leaks.len(),
        r.lookalike_domains.iter().filter(|l| l.cert_issued).count()));

    h.push_str("<h2>Breaches (HIBP)</h2>");
    if r.breaches.is_empty() { h.push_str("<div class='card ok'>None.</div>"); }
    else {
        h.push_str("<table><tr><th>Title</th><th>Date</th><th>Accounts</th><th>Data classes</th></tr>");
        for b in &r.breaches {
            h.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_esc(&b.title), html_esc(&b.breach_date.clone().unwrap_or_default()),
                b.pwn_count.map(|n| n.to_string()).unwrap_or_default(),
                html_esc(&b.data_classes.join(", "))));
        }
        h.push_str("</table>");
    }

    h.push_str("<h2>GitHub code hits</h2>");
    if r.github_leaks.is_empty() { h.push_str("<div class='card ok'>None.</div>"); }
    else {
        h.push_str("<table><tr><th>Repo</th><th>Path</th><th>Link</th></tr>");
        for h2 in &r.github_leaks {
            h.push_str(&format!("<tr><td>{}</td><td>{}</td><td><a href='{}'>open</a></td></tr>",
                html_esc(&h2.repo), html_esc(&h2.path), html_esc(&h2.html_url)));
        }
        h.push_str("</table>");
    }

    h.push_str("<h2>Lookalike domains</h2>");
    let cert: Vec<_> = r.lookalike_domains.iter().filter(|l| l.cert_issued).collect();
    if cert.is_empty() { h.push_str("<div class='card ok'>No cert-bearing variants.</div>"); }
    else {
        h.push_str("<table><tr><th>Variant</th><th>Type</th><th>Cert at</th></tr>");
        for la in cert {
            h.push_str(&format!("<tr><td class='err'>{}</td><td>{}</td><td>{}</td></tr>",
                html_esc(&la.variant), html_esc(&la.variant_type),
                html_esc(&la.recent_cert_at.clone().unwrap_or_default())));
        }
        h.push_str("</table>");
    }
    h.push_str(HTML_FOOT);
    h
}
