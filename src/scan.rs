//! Thin wrapper around spf/dkim/dmarc/scoring so server.rs + main.rs
//! share a single implementation of the "run a scan" pipeline.

use crate::{EmailReport, dkim, dmarc, scoring, spf};

pub async fn scan_domain(domain: &str) -> EmailReport {
    let s  = spf::check(domain).await;
    let dk = dkim::check(domain).await;
    let dm = dmarc::check(domain).await;
    let (score, grade, findings) = scoring::calculate(&s, &dk, &dm);
    EmailReport {
        domain:     domain.into(),
        spf: s, dkim: dk, dmarc: dm,
        score, grade, findings,
        scanned_at: chrono::Utc::now().to_rfc3339(),
    }
}
