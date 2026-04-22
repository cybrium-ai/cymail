use crate::ProtoResult;
use hickory_resolver::Resolver;
pub async fn check(domain: &str) -> ProtoResult {
    let resolver = Resolver::builder_tokio().unwrap().build();
    match resolver.txt_lookup(domain).await {
        Ok(records) => {
            for r in records.iter() { let t = r.to_string(); if t.contains("v=spf1") {
                let mut issues = Vec::new();
                if t.contains("+all") { issues.push("Permissive +all".into()); }
                let p = if t.contains("-all") { "strict" } else if t.contains("~all") { "soft" } else { "permissive" };
                return ProtoResult { configured: true, record: Some(t), policy: Some(p.into()), issues };
            }}
            ProtoResult { configured: false, record: None, policy: None, issues: vec!["No SPF record".into()] }
        }
        Err(_) => ProtoResult { configured: false, record: None, policy: None, issues: vec!["DNS failed".into()] }
    }
}
