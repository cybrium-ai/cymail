use crate::ProtoResult;
use hickory_resolver::Resolver;

pub async fn check(domain: &str) -> ProtoResult {
    let resolver = Resolver::builder_tokio().unwrap().build();
    match resolver.txt_lookup(&format!("_dmarc.{domain}")).await {
        Ok(records) => {
            for r in records.iter() {
                let t = r.to_string();
                if t.contains("v=DMARC1") {
                    let mut issues = Vec::new();
                    let p = if t.contains("p=reject") { "reject" }
                            else if t.contains("p=quarantine") { "quarantine" }
                            else { issues.push("Policy is none".into()); "none" };
                    if !t.contains("rua=") { issues.push("No aggregate reporting".into()); }

                    // v0.7.0 G4 — subdomain policy (`sp=`) inspection.
                    // Without sp=, subdomains inherit p=. The dangerous
                    // combination is p=none + no sp= which leaves the
                    // whole subdomain tree open. The other failure mode
                    // is sp= weaker than p= (a fenced apex but lax
                    // subdomains).
                    let sp = extract_sp(&t);
                    match (p, sp.as_deref()) {
                        ("none", None) => {
                            issues.push(
                                "DMARC-SP-MISSING-WHEN-P-NONE: p=none with no sp= directive — subdomains inherit none, leaving the subdomain tree wide open (CIS M365 §2.1.3)"
                                .into(),
                            );
                        }
                        ("reject", Some("none")) | ("quarantine", Some("none")) => {
                            issues.push(format!(
                                "DMARC-SP-WEAKER-THAN-P: sp=none weaker than p={p} — subdomains exempt from enforcement"
                            ));
                        }
                        ("reject", Some("quarantine")) => {
                            issues.push(
                                "DMARC-SP-WEAKER-THAN-P: sp=quarantine weaker than p=reject — subdomains get a softer policy"
                                .into(),
                            );
                        }
                        _ => {}
                    }

                    return ProtoResult {
                        configured: true,
                        record:     Some(t),
                        policy:     Some(p.into()),
                        issues,
                    };
                }
            }
            ProtoResult {
                configured: false,
                record:     None,
                policy:     None,
                issues:     vec!["No DMARC".into()],
            }
        }
        Err(_) => ProtoResult {
            configured: false,
            record:     None,
            policy:     None,
            issues:     vec!["DNS failed".into()],
        },
    }
}

/// Parse the `sp=` tag value from a DMARC record. Returns None when the
/// tag isn't present. Tags are case-insensitive per RFC 7489 §6.4.
pub fn extract_sp(record: &str) -> Option<String> {
    for raw_tag in record.split(';') {
        let tag = raw_tag.trim();
        let lower = tag.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("sp=") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sp_present() {
        assert_eq!(extract_sp("v=DMARC1; p=reject; sp=quarantine; rua=mailto:a@b.com"),
                   Some("quarantine".into()));
    }

    #[test]
    fn sp_missing() {
        assert_eq!(extract_sp("v=DMARC1; p=none; rua=mailto:a@b.com"), None);
    }

    #[test]
    fn sp_case_insensitive() {
        assert_eq!(extract_sp("v=DMARC1; p=reject; SP=NONE"), Some("none".into()));
    }
}
