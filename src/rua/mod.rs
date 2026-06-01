//! DMARC aggregate (RUA) report parsing + rollup (Sprint 98 P5 — v0.6.4).
//!
//! Subcommand `cymail rua` exposes:
//!   - `cymail rua parse <file>`  — single XML/ZIP/GZ → JSON
//!   - `cymail rua aggregate --dir DIR --domain example.com` — rollup
//!
//! No SQLite in v0.6.4 — we ship the parser + in-memory aggregate
//! first (the harder + more useful half). v0.6.4 disk persistence
//! lands as a follow-up; the in-memory rollup is JSON-serialisable so
//! the operator can pipe to jq / store wherever they like.

pub mod aggregate;
pub mod xml_parser;

pub use aggregate::{parse_file, rollup_dir, rollup_from_reports, RuaRollup, SourceIpStats, OrgStats};
pub use xml_parser::{parse, DmarcReport, DmarcRecord, AuthResult};
