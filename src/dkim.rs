use crate::ProtoResult;
use base64::Engine;
use hickory_resolver::Resolver;

const DEFAULT_SELECTORS: &[&str] = &[
    "default", "google", "selector1", "selector2", "k1", "dkim", "mail",
];

pub async fn check(domain: &str) -> ProtoResult {
    let resolver = Resolver::builder_tokio().unwrap().build();
    for sel in DEFAULT_SELECTORS {
        if let Ok(records) = resolver.txt_lookup(&format!("{sel}._domainkey.{domain}")).await {
            for r in records.iter() {
                let t = r.to_string();
                if t.contains("p=") {
                    let mut issues = Vec::new();
                    // v0.7.0 G3 — RSA key-bit extraction. NIST SP 800-131A
                    // retires 1024-bit RSA signatures. CIS M365 §2.1.2 wants
                    // ≥2048 bits.
                    if let Some(bits) = extract_rsa_key_bits(&t) {
                        if bits < 2048 {
                            issues.push(format!(
                                "DKIM-KEY-WEAK: selector {sel} uses RSA-{bits} key (NIST SP 800-131A retires <2048 — recommend rotation to RSA-2048 or Ed25519)"
                            ));
                        }
                    }
                    return ProtoResult {
                        configured: true,
                        record:     Some(t),
                        policy:     Some((*sel).into()),
                        issues,
                    };
                }
            }
        }
    }
    ProtoResult {
        configured: false,
        record:     None,
        policy:     None,
        issues:     vec!["No DKIM found".into()],
    }
}

/// Extract the bit length of an RSA public key from a DKIM TXT record.
///
/// DKIM records look like `v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUA...`.
/// The p= tag value is a base64-encoded SubjectPublicKeyInfo (ASN.1 DER).
/// We decode it and walk: SEQUENCE { algorithm, BIT STRING { SEQUENCE { modulus, exponent } } }.
/// The modulus bit length is the key size.
///
/// Returns `None` if the record doesn't have a p= tag, isn't valid base64,
/// or the DER doesn't parse — being conservative is safer than emitting
/// a false positive.
pub fn extract_rsa_key_bits(record: &str) -> Option<u32> {
    // Find p= tag.
    let p_start = record.find("p=")?;
    let after_p = &record[p_start + 2..];
    let end = after_p
        .find(|c: char| c == ';' || c.is_whitespace() || c == '"')
        .unwrap_or(after_p.len());
    let b64 = &after_p[..end].trim();
    if b64.is_empty() { return None; }

    let der = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()).ok()?;

    // DER walk for SubjectPublicKeyInfo:
    //   SEQUENCE {                       0x30
    //     SEQUENCE { algorithm + params } 0x30
    //     BIT STRING {                    0x03
    //       0x00 (unused-bits byte)
    //       SEQUENCE {                    0x30
    //         INTEGER modulus,            0x02
    //         INTEGER exponent
    //       }
    //     }
    //   }
    let mut i = 0;
    if *der.get(i)? != 0x30 { return None; }
    i += 1;
    let _outer_len = read_der_length(&der, &mut i)?;

    // Skip the inner algorithm SEQUENCE.
    if *der.get(i)? != 0x30 { return None; }
    i += 1;
    let alg_len = read_der_length(&der, &mut i)?;
    i += alg_len;

    // BIT STRING.
    if *der.get(i)? != 0x03 { return None; }
    i += 1;
    let _bs_len = read_der_length(&der, &mut i)?;
    i += 1; // unused-bits byte (always 0 for SPKI)

    // Inner SEQUENCE { modulus INTEGER, exponent INTEGER }.
    if *der.get(i)? != 0x30 { return None; }
    i += 1;
    let _seq_len = read_der_length(&der, &mut i)?;

    // INTEGER (modulus).
    if *der.get(i)? != 0x02 { return None; }
    i += 1;
    let mod_len = read_der_length(&der, &mut i)?;
    let mod_bytes = der.get(i..i + mod_len)?;

    // Strip leading zero sign-pad if present.
    let stripped = if mod_bytes.first() == Some(&0x00) { &mod_bytes[1..] } else { mod_bytes };
    Some((stripped.len() as u32) * 8)
}

fn read_der_length(buf: &[u8], i: &mut usize) -> Option<usize> {
    let first = *buf.get(*i)?;
    *i += 1;
    if first < 0x80 { return Some(first as usize); }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 { return None; }
    let mut len = 0usize;
    for _ in 0..n {
        len = (len << 8) | (*buf.get(*i)? as usize);
        *i += 1;
    }
    Some(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_p_tag_returns_none() {
        assert_eq!(extract_rsa_key_bits("v=DKIM1; k=rsa"), None);
    }

    #[test]
    fn invalid_base64_returns_none() {
        assert_eq!(extract_rsa_key_bits("v=DKIM1; p=!!!"), None);
    }

    #[test]
    fn ignores_record_without_p_tag() {
        // Real-shaped record without the p= portion (e.g. revoked key).
        assert_eq!(extract_rsa_key_bits("v=DKIM1; k=rsa; t=y"), None);
    }
}
