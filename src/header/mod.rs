//! Email header forensics (Sprint 98 P6 — v0.6.5).
//!
//! Subcommand `cymail header <eml-file>` parses one received email
//! and runs four classes of check:
//!
//!   1. Received: chain walk (received.rs)
//!   2. ARC seal structural validation (arc.rs)
//!   3. DKIM body-hash recompute (dkim_body.rs)
//!   4. Authentication-Results header sanity (this module)
//!
//! No external state needed for #1, #2, #4. #3 only needs the
//! body bytes. Full DKIM signature crypto verification (DNS pubkey
//! fetch + signature math) is a Sprint 99 follow-up; this v0.6.5
//! body-hash check already catches in-flight body tampering, which
//! is the most damning DKIM failure mode.

pub mod arc;
pub mod dkim_body;
pub mod received;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderReport {
    pub file:                String,
    pub scanned_at:          String,
    pub from_address:        Option<String>,
    pub subject:             Option<String>,
    pub message_id:          Option<String>,
    pub received:            received::ReceivedAnalysis,
    pub arc:                 arc::ArcAnalysis,
    pub dkim_body_checks:    Vec<dkim_body::DkimBodyCheck>,
    pub auth_results_raw:    Vec<String>,
    pub findings:            Vec<HeaderFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderFinding {
    pub id:        String,
    pub severity:  String,
    pub message:   String,
}

/// Top-level: parse a raw RFC 5322 message and run every check.
pub fn analyze(path: &std::path::Path) -> Result<HeaderReport, String> {
    let raw = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    // Split the message at the first blank line. Everything before
    // is headers (folded across CRLFs), after is body.
    let (head, body) = split_message(&raw);
    let headers = unfold_headers(head);

    let received_lines = headers_named(&headers, "received");
    let dkim_lines     = headers_named(&headers, "dkim-signature");
    let aar_lines      = headers_named(&headers, "arc-authentication-results");
    let asig_lines     = headers_named(&headers, "arc-message-signature");
    let aseal_lines    = headers_named(&headers, "arc-seal");

    let from_address = headers_named(&headers, "from").into_iter().next();
    let subject      = headers_named(&headers, "subject").into_iter().next();
    let message_id   = headers_named(&headers, "message-id").into_iter().next();

    let received_analysis = received::analyze(&received_lines);
    let arc_analysis      = arc::analyze(&aar_lines, &asig_lines, &aseal_lines);
    let dkim_checks       = dkim_body::check_all(&dkim_lines, body);
    let auth_results_raw  = headers_named(&headers, "authentication-results");

    // Aggregate findings into the platform-compatible shape.
    let mut findings = Vec::new();
    for f in &received_analysis.findings {
        findings.push(HeaderFinding {
            id: "cymail.header.received_anomaly".into(),
            severity: if f.contains("forged") || f.contains("backwards") { "high".into() } else { "medium".into() },
            message: f.clone(),
        });
    }
    for f in &arc_analysis.findings {
        findings.push(HeaderFinding {
            id: "cymail.header.arc_anomaly".into(),
            severity: if f.contains("cv=fail") { "high".into() } else { "medium".into() },
            message: f.clone(),
        });
    }
    for c in &dkim_checks {
        if !c.match_ {
            findings.push(HeaderFinding {
                id: "cymail.header.dkim_body_mismatch".into(),
                severity: "critical".into(),
                message: format!("DKIM body hash mismatch for {}/{} ({})",
                    c.selector, c.domain,
                    c.note.clone().unwrap_or_default()),
            });
        }
    }

    Ok(HeaderReport {
        file:           path.display().to_string(),
        scanned_at:     chrono::Utc::now().to_rfc3339(),
        from_address,
        subject,
        message_id,
        received: received_analysis,
        arc: arc_analysis,
        dkim_body_checks: dkim_checks,
        auth_results_raw,
        findings,
    })
}

// ─── Tiny RFC 5322 header splitter ────────────────────────────────
//
// We don't pull in `mailparse` for this — RFC 5322 has only a few
// pieces we need (header/body split, unfolding, name lookup). Less
// dep surface, easier to audit.

fn split_message(raw: &[u8]) -> (&[u8], &[u8]) {
    // Find the first occurrence of "\r\n\r\n" or "\n\n".
    if let Some(idx) = find_subseq(raw, b"\r\n\r\n") {
        return (&raw[..idx], &raw[idx + 4..]);
    }
    if let Some(idx) = find_subseq(raw, b"\n\n") {
        return (&raw[..idx], &raw[idx + 2..]);
    }
    (raw, &[])
}

fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() { return None; }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Returns a Vec<(name_lowercase, value)> with folded CRLF/SP/HTAB
/// continuations joined into single logical headers.
fn unfold_headers(head: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(head).replace("\r\n", "\n");
    let mut out: Vec<(String, String)> = Vec::new();
    let mut cur: Option<String> = None;
    for line in text.split('\n') {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(c) = cur.as_mut() {
                c.push(' ');
                c.push_str(line.trim_start());
            }
            continue;
        }
        if let Some(c) = cur.take() {
            push_kv(&mut out, &c);
        }
        cur = Some(line.to_string());
    }
    if let Some(c) = cur { push_kv(&mut out, &c); }
    out
}

fn push_kv(out: &mut Vec<(String, String)>, line: &str) {
    if let Some(colon) = line.find(':') {
        let name = line[..colon].trim().to_lowercase();
        let value = line[colon + 1..].trim().to_string();
        out.push((name, value));
    }
}

fn headers_named(headers: &[(String, String)], name: &str) -> Vec<String> {
    headers.iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_message_finds_blank_line() {
        let raw = b"Subject: x\r\nFrom: y\r\n\r\nthe body";
        let (h, b) = split_message(raw);
        assert!(std::str::from_utf8(h).unwrap().contains("Subject"));
        assert_eq!(b, b"the body");
    }

    #[test]
    fn unfold_joins_folded_lines() {
        let head = b"Subject: hello\r\n world\r\nFrom: x\r\n";
        let h = unfold_headers(head);
        let subj = h.iter().find(|(k, _)| k == "subject").unwrap();
        assert_eq!(subj.1, "hello world");
    }

    #[test]
    fn analyze_minimal_message() {
        let tmp = std::env::temp_dir().join("cymail-test.eml");
        std::fs::write(&tmp, b"From: alice@example.com\r\nSubject: hi\r\nReceived: from a by b ; Wed, 11 Dec 2024 14:30:00 +0000\r\n\r\nhello").unwrap();
        let r = analyze(&tmp).unwrap();
        assert_eq!(r.from_address.as_deref(), Some("alice@example.com"));
        assert_eq!(r.subject.as_deref(),      Some("hi"));
        assert_eq!(r.received.hops.len(), 1);
    }
}
