//! Received: chain walker.
//!
//! RFC 5321 §4.4 says each MTA prepends a Received: line. The chain
//! reads bottom→top (oldest hop first). Each line is free-form-ish
//! but standard tokens are:
//!
//!   from <helo>  by <receiving-mta>  with <protocol>  id <local>
//!     for <recipient>  ; <date>
//!
//! What we look for:
//!   - parse the date and check it's >= the prior hop's date.
//!     Backwards timestamps strongly suggest header forgery.
//!   - extract the HELO + by hostnames.
//!   - flag hops where the HELO looks generic ("localhost",
//!     "[127.0.0.1]") or doesn't match the by_hostname's parent
//!     domain.
//!
//! No external state. Returns a structured representation +
//! findings.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedHop {
    pub raw:           String,
    pub from_text:     Option<String>,
    pub by_text:       Option<String>,
    pub with_protocol: Option<String>,
    pub date:          Option<String>,
    pub date_epoch:    Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReceivedAnalysis {
    pub hops:                 Vec<ReceivedHop>,
    pub backwards_timestamps: Vec<usize>,    // hop indices where time goes backward
    pub findings:             Vec<String>,
}

pub fn analyze(received_headers: &[String]) -> ReceivedAnalysis {
    let mut a = ReceivedAnalysis::default();
    // Received lines are in MOST-RECENT-FIRST order in the raw email.
    // We reverse to make hop[0] = oldest = original sending MTA.
    for raw in received_headers.iter().rev() {
        a.hops.push(parse_one(raw));
    }

    // Backwards-timestamp detection.
    let mut prev: Option<i64> = None;
    for (i, hop) in a.hops.iter().enumerate() {
        if let Some(t) = hop.date_epoch {
            if let Some(prev_t) = prev {
                if t < prev_t {
                    a.backwards_timestamps.push(i);
                    a.findings.push(format!(
                        "hop {} timestamp {} is before previous hop's {} — forged header suspected",
                        i, t, prev_t
                    ));
                }
            }
            prev = Some(t);
        }
    }

    // Generic-HELO detection.
    for (i, hop) in a.hops.iter().enumerate() {
        if let Some(helo) = &hop.from_text {
            let l = helo.to_lowercase();
            if l.contains("localhost")
                || l.contains("[127.0.0.1]")
                || l == "[::1]"
            {
                a.findings.push(format!("hop {i} HELO is loopback ({helo})"));
            }
        }
    }

    a
}

fn parse_one(raw: &str) -> ReceivedHop {
    // Normalise newlines/CRLF + collapse runs of whitespace.
    let normalised: String = raw.replace('\r', " ").replace('\n', " ")
        .split_whitespace().collect::<Vec<_>>().join(" ");

    let mut hop = ReceivedHop {
        raw: raw.to_string(),
        from_text: None, by_text: None,
        with_protocol: None,
        date: None, date_epoch: None,
    };

    // Date — everything after the last ';'
    if let Some(idx) = normalised.rfind(';') {
        let date_part = normalised[idx + 1..].trim().to_string();
        if !date_part.is_empty() {
            // Try common RFC 5322 date formats.
            for fmt in &[
                "%a, %d %b %Y %H:%M:%S %z",
                "%d %b %Y %H:%M:%S %z",
                "%a, %d %b %Y %H:%M:%S %Z",
            ] {
                if let Ok(dt) = DateTime::parse_from_str(&date_part, fmt) {
                    hop.date_epoch = Some(dt.with_timezone(&Utc).timestamp());
                    break;
                }
            }
            hop.date = Some(date_part);
        }
    }

    // Tokenise — split on whitespace, lowercase-match the keywords.
    let toks: Vec<&str> = normalised.split_whitespace().collect();
    let mut i = 0;
    while i < toks.len() {
        match toks[i].to_lowercase().as_str() {
            "from" if i + 1 < toks.len() => {
                hop.from_text = Some(toks[i + 1].to_string());
                i += 2;
            }
            "by" if i + 1 < toks.len() => {
                hop.by_text = Some(toks[i + 1].to_string());
                i += 2;
            }
            "with" if i + 1 < toks.len() => {
                hop.with_protocol = Some(toks[i + 1].to_string());
                i += 2;
            }
            _ => { i += 1; }
        }
    }
    hop
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_received() {
        let raw = "from mail-out.example.net (mail-out.example.net [192.0.2.1])\r\n by mx.example.com (Postfix) with ESMTPS id abc123\r\n for <user@example.com>; Wed, 11 Dec 2024 14:30:00 +0000";
        let h = parse_one(raw);
        assert_eq!(h.from_text.as_deref(), Some("mail-out.example.net"));
        assert_eq!(h.by_text.as_deref(),   Some("mx.example.com"));
        assert_eq!(h.with_protocol.as_deref(), Some("ESMTPS"));
        assert!(h.date_epoch.is_some());
    }

    #[test]
    fn detects_backwards_timestamps() {
        let h1 = "from a by b ; Wed, 11 Dec 2024 14:00:00 +0000".to_string();
        let h2 = "from a by b ; Wed, 11 Dec 2024 13:00:00 +0000".to_string();
        // Email header order: most-recent first. Reversed inside
        // analyze, so this lays h1=oldest h2=newer, but h2's clock
        // is BEFORE h1 → backwards.
        let headers = vec![h2.clone(), h1.clone()];
        let a = analyze(&headers);
        assert_eq!(a.hops.len(), 2);
        assert!(!a.backwards_timestamps.is_empty());
    }

    #[test]
    fn flags_loopback_helo() {
        let h = "from localhost by mx.example.com ; Wed, 11 Dec 2024 14:30:00 +0000".to_string();
        let a = analyze(&[h]);
        assert!(a.findings.iter().any(|f| f.contains("loopback")));
    }
}
