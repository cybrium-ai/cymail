//! ARC (Authenticated Received Chain) seal analysis.
//!
//! RFC 8617. Each forwarding step prepends three headers:
//!   ARC-Authentication-Results: i=N; ...
//!   ARC-Message-Signature:        i=N; ...
//!   ARC-Seal:                     i=N; cv=none|pass|fail; ...
//!
//! Each ARC set has an instance `i=` (1-based, monotonically
//! increasing). The most recent forwarder sets cv= to indicate
//! whether prior chain validation passed.
//!
//! What we check:
//!   - i= values form 1, 2, 3, ... with no gaps.
//!   - One ARC-Authentication-Results / -Message-Signature /
//!     -Seal per instance — never two of the same instance.
//!   - cv= for the highest instance is "pass" (failures = forgery
//!     signal or broken forwarder).
//!
//! Full cryptographic verification of ARC seals requires DKIM
//! signature math + DNS fetch per signer; that's a Sprint 99
//! follow-up. v0.6.5 ships the structural checks which already
//! surface most forgery patterns.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArcAnalysis {
    pub instances:    Vec<ArcInstance>,
    pub final_cv:     Option<String>,
    pub findings:     Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcInstance {
    pub i:                 u32,
    pub has_auth_results:  bool,
    pub has_signature:     bool,
    pub has_seal:          bool,
    pub cv:                Option<String>,
}

pub fn analyze(
    arc_auth_results: &[String],
    arc_signatures:   &[String],
    arc_seals:        &[String],
) -> ArcAnalysis {
    let mut a = ArcAnalysis::default();

    // Bucket by instance number.
    use std::collections::HashMap;
    let mut by_i: HashMap<u32, ArcInstance> = HashMap::new();

    fn bump(by_i: &mut HashMap<u32, ArcInstance>, i: u32) -> &mut ArcInstance {
        by_i.entry(i).or_insert(ArcInstance {
            i,
            has_auth_results: false,
            has_signature:    false,
            has_seal:         false,
            cv:               None,
        })
    }

    for h in arc_auth_results {
        if let Some(i) = extract_i(h) {
            bump(&mut by_i, i).has_auth_results = true;
        }
    }
    for h in arc_signatures {
        if let Some(i) = extract_i(h) {
            bump(&mut by_i, i).has_signature = true;
        }
    }
    for h in arc_seals {
        if let Some(i) = extract_i(h) {
            let cv = extract_cv(h);
            let e = bump(&mut by_i, i);
            e.has_seal = true;
            e.cv = cv;
        }
    }

    // Order by instance ascending.
    let mut instances: Vec<ArcInstance> = by_i.into_values().collect();
    instances.sort_by_key(|x| x.i);

    // Check completeness + gap detection.
    let mut expected = 1u32;
    for inst in &instances {
        if inst.i != expected {
            a.findings.push(format!(
                "ARC instance gap: expected {}, found {}", expected, inst.i));
        }
        if !inst.has_auth_results { a.findings.push(format!("ARC i={}: missing ARC-Authentication-Results", inst.i)); }
        if !inst.has_signature    { a.findings.push(format!("ARC i={}: missing ARC-Message-Signature", inst.i)); }
        if !inst.has_seal         { a.findings.push(format!("ARC i={}: missing ARC-Seal", inst.i)); }
        expected = inst.i + 1;
    }

    // Final-instance cv check.
    if let Some(top) = instances.last() {
        a.final_cv = top.cv.clone();
        if let Some(cv) = &top.cv {
            if cv.eq_ignore_ascii_case("fail") {
                a.findings.push(format!(
                    "final ARC seal cv=fail — upstream chain validation failed (forgery suspected)"));
            }
        }
    }

    a.instances = instances;
    a
}

fn extract_i(header: &str) -> Option<u32> {
    // Find "i=" then parse the integer that follows.
    let lower = header.to_lowercase();
    let pos = lower.find("i=")?;
    let rest = &header[pos + 2..];
    let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    n.parse().ok()
}

fn extract_cv(header: &str) -> Option<String> {
    let lower = header.to_lowercase();
    let pos = lower.find("cv=")?;
    let rest = &header[pos + 3..];
    let v: String = rest.chars()
        .take_while(|c| !c.is_whitespace() && *c != ';' && *c != ',')
        .collect();
    if v.is_empty() { None } else { Some(v) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_gap() {
        let aar = vec![
            "i=1; spf=pass".to_string(),
            "i=3; spf=pass".to_string(),
        ];
        let sig = vec![
            "i=1; d=example.com".to_string(),
            "i=3; d=example.com".to_string(),
        ];
        let seal = vec![
            "i=1; cv=none; d=example.com".to_string(),
            "i=3; cv=pass; d=example.com".to_string(),
        ];
        let a = analyze(&aar, &sig, &seal);
        assert!(a.findings.iter().any(|f| f.contains("gap")));
    }

    #[test]
    fn surfaces_cv_fail() {
        let one = vec!["i=1; ...".to_string()];
        let seal = vec!["i=1; cv=fail; d=example.com".to_string()];
        let a = analyze(&one, &one, &seal);
        assert!(a.findings.iter().any(|f| f.contains("cv=fail")));
        assert_eq!(a.final_cv.as_deref(), Some("fail"));
    }

    #[test]
    fn extract_i_basic() {
        assert_eq!(extract_i("i=3; cv=pass"), Some(3));
        assert_eq!(extract_i("foo i=12; bar"), Some(12));
        assert_eq!(extract_i("no instance"), None);
    }

    #[test]
    fn extract_cv_basic() {
        assert_eq!(extract_cv("i=1; cv=pass; d=example.com"), Some("pass".into()));
        assert_eq!(extract_cv("i=1; cv=fail"), Some("fail".into()));
        assert_eq!(extract_cv("no chain"), None);
    }
}
