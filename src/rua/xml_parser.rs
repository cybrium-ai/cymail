//! DMARC aggregate (RUA) XML parser.
//!
//! Spec: RFC 7489 §A.1. Aggregate reports are XML documents wrapped
//! by reporting orgs (Google, Microsoft, Yahoo, Outlook, Amazon SES,
//! Mailgun, etc.) and emailed to the `rua=` address in your DMARC
//! TXT record. Shape:
//!
//! <feedback>
//!   <report_metadata>
//!     <org_name>google.com</org_name>
//!     <email>noreply-dmarc-support@google.com</email>
//!     <report_id>1234</report_id>
//!     <date_range><begin>...</begin><end>...</end></date_range>
//!   </report_metadata>
//!   <policy_published>
//!     <domain>example.com</domain>
//!     <adkim>r</adkim><aspf>r</aspf>
//!     <p>none|quarantine|reject</p>
//!     <sp>none</sp>
//!     <pct>100</pct>
//!   </policy_published>
//!   <record>
//!     <row>
//!       <source_ip>1.2.3.4</source_ip>
//!       <count>42</count>
//!       <policy_evaluated>
//!         <disposition>none</disposition>
//!         <dkim>pass|fail</dkim>
//!         <spf>pass|fail</spf>
//!       </policy_evaluated>
//!     </row>
//!     <identifiers><header_from>example.com</header_from></identifiers>
//!     <auth_results>
//!       <dkim><domain>...</domain><result>pass</result></dkim>
//!       <spf><domain>...</domain><result>pass</result></spf>
//!     </auth_results>
//!   </record>
//!   ...
//! </feedback>
//!
//! quick-xml walks events; we accumulate into the structs below.

use serde::{Deserialize, Serialize};

use quick_xml::events::Event;
use quick_xml::reader::Reader;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DmarcReport {
    pub org_name:        String,
    pub email:           String,
    pub report_id:       String,
    pub date_begin:      Option<i64>,
    pub date_end:        Option<i64>,
    pub policy_domain:   String,
    pub policy_adkim:    Option<String>,
    pub policy_aspf:     Option<String>,
    pub policy_p:        Option<String>,
    pub policy_sp:       Option<String>,
    pub policy_pct:      Option<u32>,
    pub records:         Vec<DmarcRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DmarcRecord {
    pub source_ip:        String,
    pub count:            u32,
    pub disposition:      String,
    pub dkim_aligned:     bool,
    pub spf_aligned:      bool,
    pub header_from:      Option<String>,
    pub envelope_to:      Option<String>,
    pub envelope_from:    Option<String>,
    pub auth_dkim:        Vec<AuthResult>,
    pub auth_spf:         Vec<AuthResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthResult {
    pub domain:       String,
    pub result:       String,    // pass / fail / none / softfail / temperror / permerror
    pub selector:     Option<String>,    // DKIM only
}

/// Parse XML bytes into a DmarcReport. Returns Err on malformed XML
/// or missing required fields (org_name/policy_domain).
pub fn parse(xml: &[u8]) -> Result<DmarcReport, String> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut rpt = DmarcReport::default();
    let mut stack: Vec<String> = Vec::new();
    let mut cur_text = String::new();
    let mut cur_record: Option<DmarcRecord> = None;
    let mut cur_dkim: Option<AuthResult> = None;
    let mut cur_spf:  Option<AuthResult> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(format!("xml read error: {e}")),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = std::str::from_utf8(e.name().as_ref()).unwrap_or("").to_string();
                stack.push(name.clone());
                cur_text.clear();
                if name == "record" { cur_record = Some(DmarcRecord::default()); }
                if name == "dkim" && stack.contains(&"auth_results".to_string()) {
                    cur_dkim = Some(AuthResult::default());
                }
                if name == "spf" && stack.contains(&"auth_results".to_string()) {
                    cur_spf = Some(AuthResult::default());
                }
            }
            Ok(Event::End(e)) => {
                let name = std::str::from_utf8(e.name().as_ref()).unwrap_or("").to_string();
                let value = cur_text.trim().to_string();

                // Decide where to stash by *current* stack context.
                if stack.contains(&"report_metadata".to_string()) {
                    if stack.contains(&"date_range".to_string()) {
                        if name == "begin" { rpt.date_begin = value.parse().ok(); }
                        if name == "end"   { rpt.date_end   = value.parse().ok(); }
                    } else {
                        match name.as_str() {
                            "org_name"  => rpt.org_name  = value,
                            "email"     => rpt.email     = value,
                            "report_id" => rpt.report_id = value,
                            _ => {}
                        }
                    }
                } else if stack.contains(&"policy_published".to_string()) {
                    match name.as_str() {
                        "domain" => rpt.policy_domain = value,
                        "adkim"  => rpt.policy_adkim = Some(value),
                        "aspf"   => rpt.policy_aspf  = Some(value),
                        "p"      => rpt.policy_p     = Some(value),
                        "sp"     => rpt.policy_sp    = Some(value),
                        "pct"    => rpt.policy_pct   = value.parse().ok(),
                        _ => {}
                    }
                } else if let Some(rec) = cur_record.as_mut() {
                    if stack.contains(&"row".to_string()) {
                        match name.as_str() {
                            "source_ip"   => rec.source_ip   = value,
                            "count"       => rec.count       = value.parse().unwrap_or(0),
                            "disposition" => rec.disposition = value,
                            "dkim"        => rec.dkim_aligned = value.eq_ignore_ascii_case("pass"),
                            "spf"         => rec.spf_aligned  = value.eq_ignore_ascii_case("pass"),
                            _ => {}
                        }
                    } else if stack.contains(&"identifiers".to_string()) {
                        match name.as_str() {
                            "header_from"   => rec.header_from   = Some(value),
                            "envelope_to"   => rec.envelope_to   = Some(value),
                            "envelope_from" => rec.envelope_from = Some(value),
                            _ => {}
                        }
                    } else if stack.contains(&"auth_results".to_string()) {
                        if let Some(d) = cur_dkim.as_mut() {
                            match name.as_str() {
                                "domain"   => d.domain   = value.clone(),
                                "result"   => d.result   = value.clone(),
                                "selector" => d.selector = Some(value.clone()),
                                "dkim" => {
                                    rec.auth_dkim.push(d.clone());
                                    cur_dkim = None;
                                }
                                _ => {}
                            }
                        }
                        if let Some(s) = cur_spf.as_mut() {
                            match name.as_str() {
                                "domain" => s.domain = value.clone(),
                                "result" => s.result = value.clone(),
                                "spf" => {
                                    rec.auth_spf.push(s.clone());
                                    cur_spf = None;
                                }
                                _ => {}
                            }
                        }
                    }
                    if name == "record" {
                        rpt.records.push(rec.clone());
                        cur_record = None;
                    }
                }

                stack.pop();
                cur_text.clear();
            }
            Ok(Event::Text(e)) => {
                if let Ok(s) = e.unescape() {
                    cur_text.push_str(&s);
                }
            }
            _ => {}
        }
        buf.clear();
    }

    if rpt.org_name.is_empty() {
        return Err("no <org_name> found — not a valid DMARC aggregate report".into());
    }
    Ok(rpt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>123456789</report_id>
    <date_range><begin>1735689600</begin><end>1735776000</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>quarantine</p>
    <sp>quarantine</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>209.85.220.41</source_ip>
      <count>5</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><selector>google</selector><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>1.2.3.4</source_ip>
      <count>42</count>
      <policy_evaluated>
        <disposition>quarantine</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>fail</result></dkim>
      <spf><domain>impersonator.example</domain><result>fail</result></spf>
    </auth_results>
  </record>
</feedback>"#;

    #[test]
    fn parses_google_sample() {
        let r = parse(SAMPLE.as_bytes()).expect("must parse");
        assert_eq!(r.org_name, "google.com");
        assert_eq!(r.policy_domain, "example.com");
        assert_eq!(r.policy_p.as_deref(), Some("quarantine"));
        assert_eq!(r.records.len(), 2);

        let aligned = &r.records[0];
        assert_eq!(aligned.count, 5);
        assert!(aligned.dkim_aligned && aligned.spf_aligned);
        assert_eq!(aligned.auth_dkim.len(), 1);
        assert_eq!(aligned.auth_dkim[0].selector.as_deref(), Some("google"));

        let mis = &r.records[1];
        assert_eq!(mis.count, 42);
        assert!(!mis.dkim_aligned && !mis.spf_aligned);
        assert_eq!(mis.disposition, "quarantine");
    }

    #[test]
    fn rejects_non_dmarc_xml() {
        let bad = b"<?xml version=\"1.0\"?><other><foo>bar</foo></other>";
        assert!(parse(bad).is_err());
    }
}
