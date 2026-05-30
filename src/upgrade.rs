//! `cymail upgrade` — self-update from signed GitHub Release.
//!
//! Mirrors the cybrium-cli pattern:
//!   1. Hit api.github.com/repos/cybrium-ai/cymail/releases/latest
//!   2. If `tag_name` > current version: download asset for our
//!      platform+arch, sha256-verify against the release's
//!      checksums.txt, atomically replace `current_exe()`.
//!   3. On Windows we additionally check that the new binary's
//!      Authenticode signature subject is `CN=cybrium` (the Trusted
//!      Signing identity), refusing the swap otherwise.
//!
//! `cymail update` is the lighter cousin — refresh threat-intel
//! caches (DNSBL feeds, lookalike DB) without touching the binary.
//! See update.rs.

use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug)]
pub enum UpgradeError {
    Network(String),
    NoMatchingAsset,
    DownloadFailed(String),
    ChecksumMismatch { expected: String, actual: String },
    SignatureRejected(String),
    SwapFailed(String),
    AlreadyLatest,
}

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use UpgradeError::*;
        match self {
            Network(e)              => write!(f, "network error: {e}"),
            NoMatchingAsset         => write!(f, "no release asset matches this platform+arch"),
            DownloadFailed(e)       => write!(f, "download failed: {e}"),
            ChecksumMismatch { expected, actual } => {
                write!(f, "checksum mismatch: expected {expected}, got {actual}")
            }
            SignatureRejected(s)    => write!(f, "signature rejected: {s}"),
            SwapFailed(s)           => write!(f, "binary swap failed: {s}"),
            AlreadyLatest           => write!(f, "already on latest version"),
        }
    }
}
impl std::error::Error for UpgradeError {}

pub struct UpgradeOpts {
    pub repo:         String,
    pub asset_prefix: String,
    pub http_timeout: Duration,
    pub dry_run:      bool,
}

impl Default for UpgradeOpts {
    fn default() -> Self {
        Self {
            repo:         "cybrium-ai/cymail".into(),
            asset_prefix: "cymail".into(),
            http_timeout: Duration::from_secs(60),
            dry_run:      false,
        }
    }
}

pub async fn upgrade(opts: &UpgradeOpts) -> Result<String, UpgradeError> {
    let current = env!("CARGO_PKG_VERSION");
    let asset_name = expected_asset_name(&opts.asset_prefix);

    let client = reqwest::Client::builder()
        .timeout(opts.http_timeout)
        .user_agent(format!("cymail/{current}"))
        .build()
        .map_err(|e| UpgradeError::Network(e.to_string()))?;

    let url = format!("https://api.github.com/repos/{}/releases/latest", opts.repo);
    let release: serde_json::Value = client.get(&url).send().await
        .map_err(|e| UpgradeError::Network(e.to_string()))?
        .json().await.map_err(|e| UpgradeError::Network(e.to_string()))?;

    let tag = release.get("tag_name").and_then(|v| v.as_str()).unwrap_or("");
    let latest = tag.trim_start_matches('v');
    if !is_newer(latest, current) {
        return Err(UpgradeError::AlreadyLatest);
    }

    // Find our asset + the checksums.txt
    let assets = release.get("assets").and_then(|v| v.as_array())
        .ok_or(UpgradeError::NoMatchingAsset)?;
    let asset = assets.iter().find(|a|
        a.get("name").and_then(|v| v.as_str()) == Some(asset_name.as_str())
    ).ok_or(UpgradeError::NoMatchingAsset)?;
    let asset_url = asset.get("browser_download_url").and_then(|v| v.as_str())
        .ok_or(UpgradeError::NoMatchingAsset)?
        .to_string();

    let checks_url = assets.iter()
        .find(|a| a.get("name").and_then(|v| v.as_str()) == Some("checksums.txt"))
        .and_then(|a| a.get("browser_download_url").and_then(|v| v.as_str()))
        .map(String::from);

    if opts.dry_run {
        return Ok(format!("would upgrade {current} → {latest} via {asset_url}"));
    }

    // Download to a temp file
    let bytes = client.get(&asset_url).send().await
        .map_err(|e| UpgradeError::DownloadFailed(e.to_string()))?
        .bytes().await
        .map_err(|e| UpgradeError::DownloadFailed(e.to_string()))?;

    // Verify sha256 if checksums.txt exists
    if let Some(url) = checks_url {
        let checks_body: String = client.get(&url).send().await
            .map_err(|e| UpgradeError::DownloadFailed(e.to_string()))?
            .text().await
            .map_err(|e| UpgradeError::DownloadFailed(e.to_string()))?;
        let expected = checks_body.lines()
            .find(|line| line.contains(&asset_name))
            .and_then(|line| line.split_whitespace().next())
            .map(|s| s.to_lowercase());
        if let Some(want) = expected {
            let got = sha256_hex(&bytes);
            if got != want {
                return Err(UpgradeError::ChecksumMismatch { expected: want, actual: got });
            }
        }
    }

    // Write to a temp path next to current exe, verify signature
    // (Windows), then swap.
    let current_exe = std::env::current_exe()
        .map_err(|e| UpgradeError::SwapFailed(e.to_string()))?;
    let dir = current_exe.parent().unwrap_or(std::path::Path::new("."));
    let mut tmp: PathBuf = dir.into();
    tmp.push(format!(".cymail-upgrade-{}", std::process::id()));
    std::fs::write(&tmp, &bytes).map_err(|e| UpgradeError::SwapFailed(e.to_string()))?;

    #[cfg(target_os = "windows")]
    {
        if let Err(e) = verify_windows_signature(&tmp) {
            let _ = std::fs::remove_file(&tmp);
            return Err(UpgradeError::SignatureRejected(e));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(mut p) = std::fs::metadata(&tmp).map(|m| m.permissions()) {
            p.set_mode(0o755);
            let _ = std::fs::set_permissions(&tmp, p);
        }
    }

    std::fs::rename(&tmp, &current_exe)
        .map_err(|e| UpgradeError::SwapFailed(e.to_string()))?;

    Ok(format!("upgraded {current} → {latest}"))
}

fn expected_asset_name(prefix: &str) -> String {
    let os   = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let plat = match (os, arch) {
        ("linux",   "x86_64")  => "linux-amd64",
        ("linux",   "aarch64") => "linux-arm64",
        ("macos",   "x86_64")  => "darwin-amd64",
        ("macos",   "aarch64") => "darwin-arm64",
        ("windows", "x86_64")  => "windows-amd64.exe",
        ("windows", "aarch64") => "windows-arm64.exe",
        _ => "unsupported",
    };
    format!("{prefix}-{plat}")
}

fn is_newer(latest: &str, current: &str) -> bool {
    fn parts(s: &str) -> Vec<u32> {
        s.split('.').filter_map(|p| {
            p.chars().take_while(|c| c.is_ascii_digit())
                .collect::<String>().parse::<u32>().ok()
        }).collect()
    }
    let (a, b) = (parts(latest), parts(current));
    a > b
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let hex_chars = b"0123456789abcdef";
    let mut s = String::with_capacity(out.len() * 2);
    for byte in out {
        s.push(hex_chars[(byte >> 4)   as usize] as char);
        s.push(hex_chars[(byte & 0x0f) as usize] as char);
    }
    s
}

#[cfg(target_os = "windows")]
fn verify_windows_signature(path: &std::path::Path) -> Result<(), String> {
    use std::process::Command;
    let out = Command::new("powershell")
        .args([
            "-NoProfile", "-NonInteractive", "-Command",
            &format!("$s = Get-AuthenticodeSignature '{}'; if ($s.Status -ne 'Valid') {{ throw \"$($s.Status)\" }}; $s.SignerCertificate.Subject", path.display()),
        ])
        .output()
        .map_err(|e| format!("powershell failed: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let subject = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !subject.contains("CN=cybrium") {
        return Err(format!("unexpected signer subject: {subject}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare() {
        assert!(is_newer("0.5.0", "0.4.0"));
        assert!(is_newer("0.4.1", "0.4.0"));
        assert!(!is_newer("0.4.0", "0.4.0"));
        assert!(!is_newer("0.3.9", "0.4.0"));
    }

    #[test]
    fn asset_naming() {
        // smoke: returns *something* on every platform we build for
        let n = expected_asset_name("cymail");
        assert!(n.starts_with("cymail-"));
    }
}
