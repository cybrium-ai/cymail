//! `cymail serve` — embedded Cybrium-themed web UI.
//!
//! Single-binary, no JS framework, no external assets. Routes:
//!   GET  /                — landing page with a form (domain + mode)
//!   GET  /scan?domain=x   — run + render scan
//!   GET  /discover?…      — run + render discovery
//!   GET  /reputation?…    — run + render reputation
//!   GET  /leak?…          — run + render leak
//!   GET  /<mode>.json|sarif|csv|html?domain=x  — export endpoints
//!   GET  /attest          — host hardware-RoT snapshot
//!   GET  /healthz         — for liveness probes
//!
//! Bound to 127.0.0.1 by default; --bind 0.0.0.0:NNNN to expose.
//! No auth — designed for local/container use behind the platform's
//! own ingress / reverse proxy.

use std::net::SocketAddr;

use axum::{
    extract::Query,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use serde::Deserialize;

use crate::{
    attest, discover, export, leak, reputation, scan,
};

async fn scan_domain(d: &str) -> crate::EmailReport { scan::scan_domain(d).await }

pub async fn serve(bind: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/",            get(landing))
        .route("/healthz",     get(|| async { "ok" }))
        .route("/attest",      get(handle_attest))
        .route("/scan",        get(handle_scan))
        .route("/discover",    get(handle_discover))
        .route("/reputation",  get(handle_reputation))
        .route("/leak",        get(handle_leak))
        // Export endpoints — same query params, format suffix routes
        .route("/scan.json",        get(export_scan_json))
        .route("/scan.sarif",       get(export_scan_sarif))
        .route("/scan.csv",         get(export_scan_csv))
        .route("/scan.html",        get(export_scan_html))
        .route("/discover.json",    get(export_discover_json))
        .route("/discover.sarif",   get(export_discover_sarif))
        .route("/discover.csv",     get(export_discover_csv))
        .route("/discover.html",    get(export_discover_html))
        .route("/reputation.json",  get(export_reputation_json))
        .route("/reputation.sarif", get(export_reputation_sarif))
        .route("/reputation.csv",   get(export_reputation_csv))
        .route("/reputation.html",  get(export_reputation_html))
        .route("/leak.json",        get(export_leak_json))
        .route("/leak.sarif",       get(export_leak_sarif))
        .route("/leak.csv",         get(export_leak_csv))
        .route("/leak.html",        get(export_leak_html));

    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("  cymail serve listening on http://{bind}");
    eprintln!("  (Ctrl-C to stop)");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Deserialize)]
struct DomainQ { domain: Option<String> }

fn require_domain(q: &DomainQ) -> Result<&str, Response> {
    q.domain.as_deref().filter(|s| !s.is_empty())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "domain is required").into_response())
}

// ─── Landing page ─────────────────────────────────────────────────
async fn landing() -> Html<&'static str> {
    Html(r##"<!doctype html><html><head><meta charset='utf-8'/><title>cymail — Cybrium AI</title>
<style>
body{background:#0a0a0f;color:#e8e8f0;font:14px/1.6 ui-sans-serif,system-ui,sans-serif;margin:0;padding:40px;}
.wrap{max-width:680px;margin:0 auto;}
h1{color:#a855f7;border-bottom:1px solid #2a2a35;padding-bottom:8px;}
.modes{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin:20px 0;}
.mode{background:#15151c;border:1px solid #2a2a35;border-radius:8px;padding:16px;}
.mode h3{margin:0 0 4px;color:#a855f7;font-size:14px;}
.mode p{margin:0;color:#8b8b9e;font-size:12px;}
form{margin:16px 0;}
input[type=text]{background:#15151c;border:1px solid #2a2a35;color:#e8e8f0;padding:10px 12px;border-radius:6px;width:340px;font-size:14px;}
select{background:#15151c;border:1px solid #2a2a35;color:#e8e8f0;padding:10px 12px;border-radius:6px;font-size:14px;}
button{background:#a855f7;border:none;color:white;padding:10px 18px;border-radius:6px;font-size:14px;cursor:pointer;font-weight:500;}
button:hover{background:#9333ea;}
.foot{margin-top:32px;padding-top:16px;border-top:1px solid #2a2a35;color:#8b8b9e;font-size:12px;}
a{color:#a855f7;}
</style></head><body><div class='wrap'>
<h1>cymail — Email Security Scanner</h1>
<p>Pick a mode and a domain. Results render inline; export buttons appear on the result page.</p>
<div class='modes'>
  <div class='mode'><h3>scan</h3><p>SPF / DKIM / DMARC posture + score (platform-compat schema)</p></div>
  <div class='mode'><h3>discover</h3><p>crt.sh + DNS SOA + pattern guessing + SMTP validation + EmailRep</p></div>
  <div class='mode'><h3>reputation</h3><p>DNSBL, BIMI, DANE, DNSSEC, SPF lookup count, DKIM hygiene, MX provider</p></div>
  <div class='mode'><h3>leak</h3><p>HIBP, GitHub code search, lookalike domains via crt.sh</p></div>
</div>
<form method='get' action='/scan'>
  <input type='text' name='domain' placeholder='example.com' required />
  <select name='__redir' onchange='this.form.action=this.value'>
    <option value='/scan'>scan</option>
    <option value='/discover'>discover</option>
    <option value='/reputation'>reputation</option>
    <option value='/leak'>leak</option>
  </select>
  <button type='submit'>Run</button>
</form>
<p style='color:#8b8b9e;font-size:12px'>Tip: every mode also has <code>?format=json</code> / <code>.sarif</code> / <code>.csv</code> / <code>.html</code> export endpoints.</p>
<div class='foot'>cymail · Cybrium AI · <a href='/attest'>host attest</a> · <a href='/healthz'>health</a></div>
</div></body></html>"##)
}

// ─── Inline handlers (HTML rendering of full reports) ─────────────
async fn handle_scan(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = scan_domain(d).await;
    Html(export::email_report_to_html(&r)).into_response()
}
async fn handle_discover(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = discover::run(d, &discover::DiscoverOpts::default()).await;
    Html(export::discovery_to_html(&r)).into_response()
}
async fn handle_reputation(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = reputation::run(d, &reputation::ReputationOpts::default()).await;
    Html(export::reputation_to_html(&r)).into_response()
}
async fn handle_leak(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = leak::run(d, &leak::LeakOpts::default()).await;
    Html(export::leak_to_html(&r)).into_response()
}
async fn handle_attest() -> Response {
    let r = attest::attest();
    let body = serde_json::to_string_pretty(&r).unwrap_or_default();
    json_response(body)
}

// ─── Export endpoints ─────────────────────────────────────────────
async fn export_scan_json(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = scan_domain(d).await;
    json_response(export::to_json(&r))
}
async fn export_scan_sarif(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = scan_domain(d).await;
    sarif_response(export::email_report_to_sarif(&r))
}
async fn export_scan_csv(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = scan_domain(d).await;
    csv_response(export::email_report_to_csv(&r), &format!("cymail-scan-{d}.csv"))
}
async fn export_scan_html(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = scan_domain(d).await;
    Html(export::email_report_to_html(&r)).into_response()
}

async fn export_discover_json(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = discover::run(d, &discover::DiscoverOpts::default()).await;
    json_response(export::to_json(&r))
}
async fn export_discover_sarif(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = discover::run(d, &discover::DiscoverOpts::default()).await;
    sarif_response(export::discovery_to_sarif(&r))
}
async fn export_discover_csv(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = discover::run(d, &discover::DiscoverOpts::default()).await;
    csv_response(export::discovery_to_csv(&r), &format!("cymail-discover-{d}.csv"))
}
async fn export_discover_html(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = discover::run(d, &discover::DiscoverOpts::default()).await;
    Html(export::discovery_to_html(&r)).into_response()
}

async fn export_reputation_json(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = reputation::run(d, &reputation::ReputationOpts::default()).await;
    json_response(export::to_json(&r))
}
async fn export_reputation_sarif(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = reputation::run(d, &reputation::ReputationOpts::default()).await;
    sarif_response(export::reputation_to_sarif(&r))
}
async fn export_reputation_csv(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = reputation::run(d, &reputation::ReputationOpts::default()).await;
    csv_response(export::reputation_to_csv(&r), &format!("cymail-reputation-{d}.csv"))
}
async fn export_reputation_html(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = reputation::run(d, &reputation::ReputationOpts::default()).await;
    Html(export::reputation_to_html(&r)).into_response()
}

async fn export_leak_json(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = leak::run(d, &leak::LeakOpts::default()).await;
    json_response(export::to_json(&r))
}
async fn export_leak_sarif(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = leak::run(d, &leak::LeakOpts::default()).await;
    sarif_response(export::leak_to_sarif(&r))
}
async fn export_leak_csv(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = leak::run(d, &leak::LeakOpts::default()).await;
    csv_response(export::leak_to_csv(&r), &format!("cymail-leak-{d}.csv"))
}
async fn export_leak_html(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = leak::run(d, &leak::LeakOpts::default()).await;
    Html(export::leak_to_html(&r)).into_response()
}

// ─── helpers ───────────────────────────────────────────────────────
fn json_response(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}
fn sarif_response(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/sarif+json")], body).into_response()
}
fn csv_response(body: String, filename: &str) -> Response {
    (
        [
            (header::CONTENT_TYPE,        "text/csv"),
            (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{filename}\"")),
        ],
        body,
    ).into_response()
}
