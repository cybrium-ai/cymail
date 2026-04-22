use crate::{Finding, ProtoResult};
pub fn calculate(spf: &ProtoResult, dkim: &ProtoResult, dmarc: &ProtoResult) -> (u8, String, Vec<Finding>) {
    let mut s: u8 = 0; let mut f = Vec::new();
    if spf.configured { s += 15; if spf.policy.as_deref() == Some("strict") { s += 10; } else { s += 5; } }
    else { f.push(Finding { id: "CYMAIL-SPF-001".into(), title: "No SPF".into(), severity: "high".into(), description: "No SPF — any server can spoof this domain".into() }); }
    if dkim.configured { s += 25; }
    else { f.push(Finding { id: "CYMAIL-DKIM-001".into(), title: "No DKIM".into(), severity: "high".into(), description: "No DKIM signing configured".into() }); }
    if dmarc.configured { s += 10; if dmarc.policy.as_deref() == Some("reject") { s += 15; } else if dmarc.policy.as_deref() == Some("quarantine") { s += 10; } else { s += 5; } }
    else { f.push(Finding { id: "CYMAIL-DMARC-001".into(), title: "No DMARC".into(), severity: "critical".into(), description: "No DMARC — fully spoofable".into() }); }
    s += 15; // TLS + MTA-STS placeholder
    let g = match s { 90..=100 => "A", 75..=89 => "B", 60..=74 => "C", 40..=59 => "D", _ => "F" }.into();
    (s, g, f)
}
