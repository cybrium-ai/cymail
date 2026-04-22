use crate::ProtoResult;
use hickory_resolver::Resolver;
pub async fn check(domain: &str) -> ProtoResult {
    let resolver = Resolver::builder_tokio().unwrap().build();
    for sel in &["default","google","selector1","selector2","k1","dkim","mail"] {
        if let Ok(records) = resolver.txt_lookup(&format!("{sel}._domainkey.{domain}")).await {
            for r in records.iter() { let t = r.to_string(); if t.contains("p=") {
                return ProtoResult { configured: true, record: Some(t), policy: Some((*sel).into()), issues: vec![] };
            }}
        }
    }
    ProtoResult { configured: false, record: None, policy: None, issues: vec!["No DKIM found".into()] }
}
