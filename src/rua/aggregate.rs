//! DMARC aggregate report rollup.
//!
//! Given a directory of received .xml / .xml.gz / .zip files, parse
//! each one into a DmarcReport, dedupe by report_id, and produce a
//! per-source-IP alignment rollup so the operator sees which IPs are
//! sending in their name + whether the receiving server thinks the
//! mail aligned.
//!
//! Output is JSON so the next iteration can hand it to a UI / SIEM.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::xml_parser::{parse, DmarcReport};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuaRollup {
    pub source_domain:       String,
    pub date_range:          (i64, i64),
    pub reports_seen:        usize,
    pub records_seen:        usize,
    pub messages_total:      u64,
    pub messages_aligned:    u64,
    pub by_source_ip:        Vec<SourceIpStats>,
    pub by_org:              Vec<OrgStats>,
    pub orphan_records:      u64,
    pub generated_at:        String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceIpStats {
    pub source_ip:           String,
    pub messages:            u64,
    pub dkim_aligned:        u64,
    pub spf_aligned:         u64,
    pub disposition_none:    u64,
    pub disposition_quar:    u64,
    pub disposition_reject:  u64,
    pub header_froms:        Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrgStats {
    pub org_name:            String,
    pub reports:             u64,
    pub messages_seen:       u64,
}

/// Parse one file (raw XML, gzipped XML, or ZIP containing one or
/// more XML). Returns each DmarcReport found inside.
pub fn parse_file(path: &Path) -> Result<Vec<DmarcReport>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let lower_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();

    if lower_name.ends_with(".gz") {
        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut dec = GzDecoder::new(&bytes[..]);
        let mut decompressed = Vec::new();
        dec.read_to_end(&mut decompressed).map_err(|e| format!("gunzip: {e}"))?;
        Ok(vec![parse(&decompressed)?])
    } else if lower_name.ends_with(".zip") {
        let cursor = std::io::Cursor::new(bytes);
        let mut zip = zip::ZipArchive::new(cursor).map_err(|e| format!("zip: {e}"))?;
        let mut reports = Vec::new();
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i).map_err(|e| format!("zip entry: {e}"))?;
            let ename = entry.name().to_string();
            if !ename.to_lowercase().ends_with(".xml") { continue; }
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut buf).map_err(|e| format!("zip read: {e}"))?;
            match parse(&buf) {
                Ok(r) => reports.push(r),
                Err(e) => eprintln!("  skip {ename}: {e}"),
            }
        }
        Ok(reports)
    } else {
        Ok(vec![parse(&bytes)?])
    }
}

/// Walk a directory (non-recursive) and aggregate every report.
/// Dedupes by report_id.
pub fn rollup_dir(dir: &Path, expected_domain: &str) -> Result<RuaRollup, String> {
    let mut seen_report_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut all_reports: Vec<DmarcReport> = Vec::new();

    let entries = std::fs::read_dir(dir).map_err(|e| format!("readdir {}: {e}", dir.display()))?;
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_file() { continue; }
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
        if !(name.ends_with(".xml") || name.ends_with(".xml.gz") || name.ends_with(".gz") || name.ends_with(".zip")) {
            continue;
        }
        match parse_file(&p) {
            Ok(rs) => {
                for r in rs {
                    if seen_report_ids.insert(r.report_id.clone()) {
                        all_reports.push(r);
                    }
                }
            }
            Err(e) => eprintln!("  skip {}: {e}", p.display()),
        }
    }
    Ok(rollup_from_reports(expected_domain, all_reports))
}

pub fn rollup_from_reports(expected_domain: &str, reports: Vec<DmarcReport>) -> RuaRollup {
    let mut date_begin = i64::MAX;
    let mut date_end:   i64 = 0;
    let mut by_ip: HashMap<String, SourceIpStats> = HashMap::new();
    let mut by_org: HashMap<String, OrgStats> = HashMap::new();
    let mut total_msgs = 0u64;
    let mut aligned_msgs = 0u64;
    let mut record_count = 0usize;
    let mut orphans = 0u64;

    for r in &reports {
        if let Some(b) = r.date_begin { if b < date_begin { date_begin = b; } }
        if let Some(e) = r.date_end   { if e > date_end   { date_end   = e; } }
        // Org bucket — count once per report.
        let org_entry = by_org.entry(r.org_name.clone())
            .or_insert_with(|| OrgStats { org_name: r.org_name.clone(), ..Default::default() });
        org_entry.reports += 1;

        // Skip reports unrelated to the domain we asked for. (Mailbox
        // dumps often include other domains.) "" => don't filter.
        if !expected_domain.is_empty()
            && !r.policy_domain.eq_ignore_ascii_case(expected_domain) {
            orphans += r.records.iter().map(|x| x.count as u64).sum::<u64>();
            continue;
        }

        for rec in &r.records {
            record_count += 1;
            total_msgs += rec.count as u64;
            org_entry.messages_seen += rec.count as u64;
            if rec.dkim_aligned || rec.spf_aligned { aligned_msgs += rec.count as u64; }

            let ip_entry = by_ip.entry(rec.source_ip.clone()).or_insert_with(|| SourceIpStats {
                source_ip:          rec.source_ip.clone(),
                messages:           0, dkim_aligned: 0, spf_aligned: 0,
                disposition_none:   0, disposition_quar: 0, disposition_reject: 0,
                header_froms:       Vec::new(),
            });
            ip_entry.messages += rec.count as u64;
            if rec.dkim_aligned { ip_entry.dkim_aligned += rec.count as u64; }
            if rec.spf_aligned  { ip_entry.spf_aligned  += rec.count as u64; }
            match rec.disposition.as_str() {
                "none"       => ip_entry.disposition_none   += rec.count as u64,
                "quarantine" => ip_entry.disposition_quar   += rec.count as u64,
                "reject"     => ip_entry.disposition_reject += rec.count as u64,
                _ => {}
            }
            if let Some(hf) = &rec.header_from {
                if !ip_entry.header_froms.iter().any(|h| h == hf) {
                    ip_entry.header_froms.push(hf.clone());
                }
            }
        }
    }

    let mut by_source_ip: Vec<SourceIpStats> = by_ip.into_values().collect();
    by_source_ip.sort_by(|a, b| b.messages.cmp(&a.messages));

    let mut by_org: Vec<OrgStats> = by_org.into_values().collect();
    by_org.sort_by(|a, b| b.messages_seen.cmp(&a.messages_seen));

    RuaRollup {
        source_domain:    expected_domain.to_string(),
        date_range:       (if date_begin == i64::MAX { 0 } else { date_begin }, date_end),
        reports_seen:     reports.len(),
        records_seen:     record_count,
        messages_total:   total_msgs,
        messages_aligned: aligned_msgs,
        by_source_ip,
        by_org,
        orphan_records:   orphans,
        generated_at:     chrono::Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::xml_parser::DmarcReport;

    fn fake_report(org: &str, dom: &str, records: Vec<(&str, u32, bool, bool)>) -> DmarcReport {
        DmarcReport {
            org_name: org.into(),
            email:    "x@y".into(),
            report_id: format!("{org}-{}", records.len()),
            date_begin: Some(1735689600),
            date_end:   Some(1735776000),
            policy_domain: dom.into(),
            policy_adkim: Some("r".into()),
            policy_aspf:  Some("r".into()),
            policy_p:     Some("quarantine".into()),
            policy_sp:    Some("quarantine".into()),
            policy_pct:   Some(100),
            records: records.into_iter().map(|(ip, c, dk, sp)| super::super::xml_parser::DmarcRecord {
                source_ip: ip.into(),
                count: c,
                disposition: "none".into(),
                dkim_aligned: dk,
                spf_aligned:  sp,
                header_from: Some(dom.into()),
                ..Default::default()
            }).collect(),
        }
    }

    #[test]
    fn rollup_dedupes_and_aggregates() {
        let r1 = fake_report("google.com", "example.com", vec![
            ("1.1.1.1", 10, true,  true),
            ("2.2.2.2", 5,  false, false),
        ]);
        let r2 = fake_report("microsoft.com", "example.com", vec![
            ("1.1.1.1", 20, true, true),
        ]);
        let agg = rollup_from_reports("example.com", vec![r1, r2]);
        assert_eq!(agg.reports_seen, 2);
        assert_eq!(agg.records_seen, 3);
        assert_eq!(agg.messages_total, 35);
        assert_eq!(agg.messages_aligned, 30);
        // 1.1.1.1 should show 30 total messages (10 + 20)
        let top = &agg.by_source_ip[0];
        assert_eq!(top.source_ip, "1.1.1.1");
        assert_eq!(top.messages, 30);
        assert_eq!(top.dkim_aligned, 30);
    }

    #[test]
    fn rollup_filters_other_domains() {
        let r = fake_report("google.com", "other.example", vec![("1.1.1.1", 99, false, false)]);
        let agg = rollup_from_reports("example.com", vec![r]);
        assert_eq!(agg.records_seen, 0);
        assert_eq!(agg.orphan_records, 99);
    }
}
