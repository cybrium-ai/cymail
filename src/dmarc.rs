use crate::ProtoResult;
use hickory_resolver::Resolver;
pub async fn check(domain: &str) -> ProtoResult {
    let resolver = Resolver::builder_tokio().unwrap().build();
    match resolver.txt_lookup(&format!("_dmarc.{domain}")).await {
        Ok(records) => {
            for r in records.iter() { let t = r.to_string(); if t.contains("v=DMARC1") {
                let mut issues = Vec::new();
                let p = if t.contains("p=reject") { "reject" } else if t.contains("p=quarantine") { "quarantine" } else { issues.push("Policy is none".into()); "none" };
                if !t.contains("rua=") { issues.push("No aggregate reporting".into()); }
                return ProtoResult { configured: true, record: Some(t), policy: Some(p.into()), issues };
            }}
            ProtoResult { configured: false, record: None, policy: None, issues: vec!["No DMARC".into()] }
        }
        Err(_) => ProtoResult { configured: false, record: None, policy: None, issues: vec!["DNS failed".into()] }
    }
}
