//! `cymail serve` — embedded Cybrium-branded web UI.
//!
//! Mirrors cyweb's chrome (header with real shield + wordmark SVGs,
//! sticky export pills, dark surface tokens) so cymail looks and
//! feels like the same product family. SVGs are embedded at compile
//! time via include_str! — the binary stays standalone, no external
//! asset fetches at runtime, works air-gapped.
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

use crate::{attest, discover, export, leak, reputation, scan};

// Real Cybrium branding — never substitute, see CLAUDE.md branding contract.
const SHIELD_SVG:   &str = include_str!("assets/cybrium-logo.svg");
const WORDMARK_SVG: &str = include_str!("assets/cybrium-word.svg");

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
        // Asset endpoints so the binary can serve the SVGs directly
        .route("/assets/cybrium-logo.svg", get(serve_shield))
        .route("/assets/cybrium-word.svg", get(serve_wordmark))
        // Export endpoints
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

// ─── Asset serving ────────────────────────────────────────────────
async fn serve_shield() -> Response {
    ([(header::CONTENT_TYPE, "image/svg+xml")], SHIELD_SVG).into_response()
}
async fn serve_wordmark() -> Response {
    ([(header::CONTENT_TYPE, "image/svg+xml")], WORDMARK_SVG).into_response()
}

// ─── Page header (matches cyweb's chrome exactly) ─────────────────
//
// The header lives in every page so the shell stays consistent
// across landing + every report. Layout: shield + wordmark on the
// left, mode/status pill, format-export buttons on the right.
fn page_chrome(title: &str, mode: &str, target: Option<&str>, export_base: Option<&str>) -> String {
    let target_html = match target {
        Some(t) => format!("<span class='target'>cymail · {} · <strong>{}</strong></span>",
            html_esc(mode), html_esc(t)),
        None    => format!("<span class='target'>cymail · {}</span>", html_esc(mode)),
    };
    let exports = match export_base {
        Some(base) => format!(
            "<div class='export-group'>\
              <a class='export' href='{base}.json'>JSON</a>\
              <a class='export' href='{base}.csv'>CSV</a>\
              <a class='export' href='{base}.sarif'>SARIF</a>\
              <a class='export' href='{base}.html' download>HTML</a>\
            </div>",
        ),
        None => String::new(),
    };
    format!(r##"<!doctype html><html lang='en'><head><meta charset='utf-8'/>
<meta name='viewport' content='width=device-width,initial-scale=1'/>
<title>{title}</title>
<style>
:root {{
  --bg:#0a0a13; --surface:#14141f; --surface-2:#1c1c2a; --border:#2a2a3a;
  --text:#e4e4ea; --muted:#8a8a98;
  --primary:#9747ff; --primary-2:#b074ff; --accent:#06b6d4;
  --sev-critical:#dc2626; --sev-high:#f97316; --sev-medium:#facc15;
  --sev-low:#3b82f6; --sev-info:#94a3b8; --ok:#22c55e;
}}
*{{box-sizing:border-box;}}
html,body{{margin:0;padding:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.5;min-height:100vh;}}
a{{color:var(--primary-2);text-decoration:none;}} a:hover{{text-decoration:underline;}}
code,pre{{font-family:ui-monospace,monospace;font-size:12px;}}
header{{display:flex;align-items:center;gap:16px;padding:14px 28px;background:linear-gradient(180deg,#14141f 0%,#0d0d18 100%);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10;}}
header .brand-shield{{height:30px;width:auto;}}
header .brand-word{{height:22px;width:auto;margin-left:-2px;}}
header .target{{margin-left:24px;color:var(--muted);font-family:ui-monospace,monospace;font-size:13px;}}
header .meta{{margin-left:auto;color:var(--muted);font-size:12px;}}
.export-group{{display:flex;gap:8px;margin-left:16px;}}
.export-group a.export{{background:var(--surface-2);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:6px 12px;font-size:13px;}}
.export-group a.export:hover{{border-color:var(--primary);color:var(--primary-2);text-decoration:none;}}
button{{background:var(--surface-2);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:8px 14px;cursor:pointer;font-size:13px;transition:all 120ms;}}
button:hover{{border-color:var(--primary);color:var(--primary-2);}}
button.primary{{background:var(--primary);color:white;border-color:var(--primary);}}
button.primary:hover{{background:var(--primary-2);}}
input[type=text]{{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:9px 12px;border-radius:6px;font-size:14px;font-family:ui-monospace,monospace;}}
input[type=text]:focus{{outline:none;border-color:var(--primary);}}
select{{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:9px 12px;border-radius:6px;font-size:14px;}}
main{{padding:24px 28px;max-width:1800px;margin:0 auto;}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:18px;}}
.card h2{{margin:0 0 4px;font-size:15px;font-weight:600;}}
.card .card-hint{{color:var(--muted);font-size:12px;margin:0 0 14px;}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;}}
.stat{{background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:14px;}}
.stat-value{{font-size:22px;font-weight:600;color:var(--text);}}
.stat-label{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:0.04em;margin-top:4px;}}
table{{border-collapse:collapse;width:100%;margin:6px 0;font-size:13px;}}
th,td{{border-bottom:1px solid var(--border);padding:8px 12px;text-align:left;vertical-align:top;}}
th{{color:var(--muted);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:0.04em;}}
.ok{{color:var(--ok);}} .warn{{color:var(--sev-medium);}} .err{{color:var(--sev-high);}} .crit{{color:var(--sev-critical);}}
.badge{{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;border:1px solid;}}
.badge.ok{{color:var(--ok);border-color:var(--ok);}}
.badge.warn{{color:var(--sev-medium);border-color:var(--sev-medium);}}
.badge.err{{color:var(--sev-high);border-color:var(--sev-high);}}
.badge.crit{{color:var(--sev-critical);border-color:var(--sev-critical);}}
.modes{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;}}
.mode-card{{background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:14px;cursor:pointer;}}
.mode-card:hover{{border-color:var(--primary);}}
.mode-card h3{{margin:0 0 4px;font-size:13px;color:var(--primary-2);}}
.mode-card p{{margin:0;color:var(--muted);font-size:12px;}}
.row{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}}
footer{{padding:18px 28px;color:var(--muted);font-size:12px;border-top:1px solid var(--border);text-align:center;}}
@media print{{html,body{{background:white;color:black;}} header{{background:white;}} .card,.stat,.mode-card{{background:white;}}}}
</style></head><body>
<header>
  <a href='/' aria-label='cymail home'>
    <img class='brand-shield' src='/assets/cybrium-logo.svg' alt='Cybrium shield'/>
  </a>
  <img class='brand-word' src='/assets/cybrium-word.svg' alt='CYBRIUM'/>
  {target_html}
  <span class='meta'>cymail · v{version}</span>
  {exports}
</header>
<main>"##, version = env!("CARGO_PKG_VERSION"))
}

fn page_footer() -> &'static str {
    "</main><footer>cymail · Cybrium AI · <a href='https://github.com/cybrium-ai/cymail'>github.com/cybrium-ai/cymail</a></footer></body></html>"
}

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

// ─── Landing ──────────────────────────────────────────────────────
async fn landing() -> Html<String> {
    let header = page_chrome("cymail — Email Security Scanner", "idle", None, None);
    let body = r##"<div class='card'>
  <h2>Start a scan</h2>
  <p class='card-hint'>Pick a mode + a domain. Results render inline; SARIF/CSV/JSON/HTML exports appear in the header.</p>
  <form method='get' action='/scan' id='cymail-form' class='row'>
    <input type='text' name='domain' id='domain' placeholder='example.com' required style='flex:1;min-width:280px;' />
    <select name='__mode' id='mode'>
      <option value='/scan'>scan — SPF/DKIM/DMARC posture</option>
      <option value='/discover'>discover — emails + reputation</option>
      <option value='/reputation'>reputation — DNSBL/BIMI/DANE/DNSSEC</option>
      <option value='/leak'>leak — HIBP/GitHub/lookalikes</option>
    </select>
    <button type='submit' class='primary'>Run scan</button>
  </form>
</div>

<div class='card'>
  <h2>Modes</h2>
  <p class='card-hint'>cymail unifies posture, discovery, reputation, and leak telemetry. All four work in CLI and via this UI.</p>
  <div class='modes'>
    <div class='mode-card' onclick="document.getElementById('mode').value='/scan'">
      <h3>scan</h3><p>SPF · DKIM · DMARC posture, scoring, grade. Schema is platform-locked.</p>
    </div>
    <div class='mode-card' onclick="document.getElementById('mode').value='/discover'">
      <h3>discover</h3><p>crt.sh SANs · DNS SOA · pattern guessing · SMTP RCPT TO · EmailRep.io reputation.</p>
    </div>
    <div class='mode-card' onclick="document.getElementById('mode').value='/reputation'">
      <h3>reputation</h3><p>Spamhaus/SURBL/URIBL/BRBL DNSBL · BIMI/VMC · DANE · DNSSEC · SPF lookup count · DKIM key hygiene · MX provider fingerprint.</p>
    </div>
    <div class='mode-card' onclick="document.getElementById('mode').value='/leak'">
      <h3>leak</h3><p>HIBP domain breaches · GitHub code search · lookalike domains with cert issuance (crt.sh).</p>
    </div>
  </div>
</div>

<div class='card'>
  <h2>System</h2>
  <p class='card-hint'>Embedded routes:</p>
  <p><a href='/attest'>/attest</a> — host hardware root-of-trust snapshot (TPM / Secure Enclave)<br/>
  <a href='/healthz'>/healthz</a> — liveness probe</p>
</div>

<script>
  // Drive the form action from the mode selector so we route to the
  // right /scan|/discover|/reputation|/leak handler.
  document.getElementById('mode').addEventListener('change', function(){
    document.getElementById('cymail-form').action = this.value;
  });
</script>
"##;
    Html(format!("{header}{body}{}", page_footer()))
}

// ─── Inline handlers (full HTML report renders) ───────────────────
async fn handle_scan(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = scan_domain(d).await;
    let header = page_chrome(
        &format!("cymail · scan · {d}"), "scan", Some(d),
        Some(&format!("/scan{}", qs(d))),
    );
    Html(format!("{header}{}{}", export::email_report_to_html_body(&r), page_footer())).into_response()
}
async fn handle_discover(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = discover::run(d, &discover::DiscoverOpts::default()).await;
    let header = page_chrome(
        &format!("cymail · discover · {d}"), "discover", Some(d),
        Some(&format!("/discover{}", qs(d))),
    );
    Html(format!("{header}{}{}", export::discovery_to_html_body(&r), page_footer())).into_response()
}
async fn handle_reputation(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = reputation::run(d, &reputation::ReputationOpts::default()).await;
    let header = page_chrome(
        &format!("cymail · reputation · {d}"), "reputation", Some(d),
        Some(&format!("/reputation{}", qs(d))),
    );
    Html(format!("{header}{}{}", export::reputation_to_html_body(&r), page_footer())).into_response()
}
async fn handle_leak(Query(q): Query<DomainQ>) -> Response {
    let d = match require_domain(&q) { Ok(d) => d, Err(r) => return r };
    let r = leak::run(d, &leak::LeakOpts::default()).await;
    let header = page_chrome(
        &format!("cymail · leak · {d}"), "leak", Some(d),
        Some(&format!("/leak{}", qs(d))),
    );
    Html(format!("{header}{}{}", export::leak_to_html_body(&r), page_footer())).into_response()
}
async fn handle_attest() -> Response {
    let r = attest::attest();
    let header = page_chrome("cymail · attest", "attest", None, None);
    let body = format!(
        "<div class='card'><h2>Host root-of-trust</h2>\
         <div class='grid'>\
           <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>OS</div></div>\
           <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Arch</div></div>\
           <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>RoT kind</div></div>\
           <div class='stat'><div class='stat-value'>{}</div><div class='stat-label'>Present</div></div>\
         </div>\
         <p class='card-hint'>Host: <code>{}</code> · Vendor: <code>{}</code></p>\
         </div>",
        html_esc(&r.os), html_esc(&r.arch),
        r.root_of_trust.kind.as_str(),
        if r.root_of_trust.present { "yes" } else { "no" },
        html_esc(&r.host), html_esc(&r.root_of_trust.vendor),
    );
    Html(format!("{header}{body}{}", page_footer())).into_response()
}

fn qs(domain: &str) -> String {
    // Lightweight URL-encode — the values we pass here are domain
    // names, which are ASCII-safe except for the IDN edge case.
    let encoded: String = domain.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32 & 0xff),
        })
        .collect();
    format!("?domain={encoded}")
}

// ─── Export endpoints — unchanged content-type behaviour ──────────
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
    handle_scan(Query(q)).await
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
    handle_discover(Query(q)).await
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
    handle_reputation(Query(q)).await
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
    handle_leak(Query(q)).await
}

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
