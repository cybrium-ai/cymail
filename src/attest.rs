//! `cymail attest` — emit the host's hardware root-of-trust snapshot
//! so the platform can attribute scans to a specific signing
//! identity. Detection only — no AIK signing. See hardware_rot.rs.

use serde::{Deserialize, Serialize};

use crate::hardware_rot::{self, RootOfTrust};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub host:        String,
    pub os:          String,
    pub arch:        String,
    pub root_of_trust: RootOfTrust,
    pub scanned_at:  String,
}

pub fn attest() -> AttestationReport {
    AttestationReport {
        host: hostname_or("unknown"),
        os:   std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        root_of_trust: hardware_rot::detect(),
        scanned_at:    chrono::Utc::now().to_rfc3339(),
    }
}

fn hostname_or(fallback: &str) -> String {
    // No external dep — `hostname` crate isn't worth pulling in for
    // one syscall. Linux/macOS expose /proc/sys/kernel/hostname,
    // Windows exposes COMPUTERNAME env.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| fallback.to_string())
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| fallback.to_string())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        fallback.to_string()
    }
}
