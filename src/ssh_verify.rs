//! SSH host key verification for git operations.
//!
//! Verification priority:
//!   1. Platform API (GitHub, GitLab.com, Codeberg, Bitbucket, SourceHut)
//!   2. ~/.ssh/known_hosts (plain and hashed entries)
//!   3. SSHFP DNS records (RFC 4255)
//!   4. TOFU – trust on first use (only when `add_new_key: true`)
//!
//! A "changed key" (previously seen host with a different key) is always
//! rejected regardless of the `add_new_key` setting.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use git2::cert::{CertHostkey, SshHostKeyType};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::dns::{DnsResolver, SshfpRecord};

type HmacSha1 = Hmac<Sha1>;

// ── Public API ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum VerifyResult {
	/// Key verified by a trusted source.
	Trusted,
	/// Key not previously seen; added to known_hosts (TOFU, only if allowed).
	NewKeyAdded,
	/// DANGER: previously known host now presents a different key.
	KeyChanged,
	/// Could not verify; no trusted source accepted the key.
	Unverified,
}

impl VerifyResult {
	pub fn is_ok(&self) -> bool {
		matches!(self, VerifyResult::Trusted | VerifyResult::NewKeyAdded)
	}
}

/// Verifies SSH host keys presented during git operations.
#[derive(Clone)]
pub struct SshVerifier {
	dns: Arc<DnsResolver>,
}

impl SshVerifier {
	pub fn new(dns: Arc<DnsResolver>) -> Self {
		SshVerifier { dns }
	}

	/// Verify `hostkey` for `hostname`.
	///
	/// `hostname` is the raw string git2 provides (may contain a port suffix
	/// like `github.com:22`; we strip it for lookups).
	///
	/// When `add_new_key` is true, a key that cannot be verified by any
	/// trusted source is accepted and written to known_hosts.  A *changed*
	/// key is always rejected.
	pub async fn verify(
		&self,
		hostname: &str,
		hostkey: &CertHostkey<'_>,
		add_new_key: bool,
	) -> VerifyResult {
		// Strip port suffix (git2 sometimes passes "host:22").
		let host = hostname.split(':').next().unwrap_or(hostname);

		let Some(key_bytes) = hostkey.hostkey() else {
			tracing::warn!(host, "git: host key has no raw bytes; skipping verification");
			return VerifyResult::Unverified;
		};
		let key_type = hostkey.hostkey_type();
		let Some(type_str) = key_type_str(key_type.unwrap_or(SshHostKeyType::Ed255219)) else {
			tracing::warn!(host, "git: unknown host key type; skipping verification");
			return VerifyResult::Unverified;
		};

		// ── 1. Platform API ───────────────────────────────────────────────────
		match platform_api_verify(host, key_bytes).await {
			Some(true)  => { tracing::debug!(host, "git: host key verified via platform API"); return VerifyResult::Trusted; }
			Some(false) => { tracing::warn!(host, "git: SECURITY — host key does not match platform API"); return VerifyResult::KeyChanged; }
			None        => {}
		}

		// ── 2. known_hosts ────────────────────────────────────────────────────
		match known_hosts_lookup(host, type_str, key_bytes) {
			KnownHostsResult::Match   => { tracing::debug!(host, "git: host key found in known_hosts"); return VerifyResult::Trusted; }
			KnownHostsResult::Changed => { tracing::warn!(host, "git: SECURITY — host key does not match known_hosts entry"); return VerifyResult::KeyChanged; }
			KnownHostsResult::NotFound => {}
		}

		// ── 3. SSHFP ─────────────────────────────────────────────────────────
		let sha1_fp   = hostkey.hash_sha1();
		let sha256_fp = hostkey.hash_sha256();
		let sshfp_algo = key_type_to_sshfp_algo(key_type.unwrap_or(
			SshHostKeyType::Ed255219,
		));

		if let Some(algo) = sshfp_algo {
			let dns_records = self.dns.query_sshfp(host).await;
			if !dns_records.is_empty() {
				if sshfp_matches(
					algo,
					sha1_fp.as_deref().map(|x| x.as_slice()),
					sha256_fp.as_deref().map(|x| x.as_slice()),
					&dns_records,
				) {
					tracing::info!(host, "git: host key verified via SSHFP DNS record");
					return VerifyResult::Trusted;
				} else {
					tracing::warn!(
						host,
						"git: host key does not match any SSHFP DNS record \
						 (SSHFP records exist but none match)"
					);
					return VerifyResult::Unverified;
				}
			}
		}

		// ── 4. TOFU ───────────────────────────────────────────────────────────
		if add_new_key {
			match append_known_host(host, type_str, key_bytes) {
				Ok(()) => {
					tracing::info!(
						host,
						key_type = type_str,
						"git: new host key added to known_hosts (TOFU)"
					);
					return VerifyResult::NewKeyAdded;
				}
				Err(e) => {
					tracing::warn!(host, "git: could not write to known_hosts: {e}");
					// Still accept the key this session even if we couldn't persist it.
					return VerifyResult::NewKeyAdded;
				}
			}
		}

		tracing::warn!(
			host,
			"git: host key could not be verified (no matching source found); \
			 set git_ssh_add_new_key: true to trust new keys automatically"
		);
		VerifyResult::Unverified
	}
}

// ── Platform API ─────────────────────────────────────────────────────────────

/// Try to verify the key against the hosting platform's public SSH key API.
///
/// Returns:
///   Some(true)  – key matches a key from the platform API
///   Some(false) – platform API returned keys but NONE matched (key changed)
///   None        – host is not a recognised platform or API call failed
async fn platform_api_verify(host: &str, key_bytes: &[u8]) -> Option<bool> {
	// GitHub — documented, reliable
	if host == "github.com" || host.ends_with(".github.com") {
		return check_github_api(key_bytes).await.ok();
	}

	// GitLab.com — uses the same API endpoint as self-hosted GitLab
	if host == "gitlab.com" {
		return check_gitlab_api("https://gitlab.com", key_bytes).await.ok();
	}

	// Codeberg — Forgejo-based, uses Gitea/Forgejo API
	if host == "codeberg.org" {
		return check_gitea_api("https://codeberg.org", key_bytes).await.ok();
	}

	// Bitbucket — no public SSH key API; fall through to known_hosts / SSHFP.
	// SourceHut  — no public SSH key API; fall through.

	None
}

/// GitHub: GET https://api.github.com/meta → { ssh_keys: ["AAAA…", …] }
async fn check_github_api(key_bytes: &[u8]) -> anyhow::Result<bool> {
	let client = reqwest::Client::builder()
		.user_agent("stateless-gallery/1.0 ssh-key-verify")
		.timeout(std::time::Duration::from_secs(8))
		.build()?;

	let resp: serde_json::Value = client
		.get("https://api.github.com/meta")
		.header("accept", "application/vnd.github+json")
		.send().await?
		.json().await?;

	let keys = resp["ssh_keys"].as_array()
		.ok_or_else(|| anyhow::anyhow!("ssh_keys missing"))?;

	let found = keys.iter()
		.filter_map(|k| k.as_str())
		.any(|k| openssh_blob_matches(k, key_bytes));

	// If the API returned keys but none matched, the key has changed.
	Ok(found)
}

/// GitLab: GET {base}/api/v4/metadata — SSH keys are NOT in the public API.
/// Fall back to checking known_hosts for gitlab.com.
async fn check_gitlab_api(_base: &str, _key_bytes: &[u8]) -> anyhow::Result<bool> {
	// GitLab's public REST API does not expose the SSH host key.
	// Return None (not Some(false)) so the caller tries known_hosts / SSHFP.
	anyhow::bail!("GitLab API does not expose SSH host keys")
}

/// Gitea / Forgejo: GET {base}/api/v1/settings/api — also no SSH key endpoint.
/// Codeberg and similar Forgejo instances don't expose host keys via API.
async fn check_gitea_api(_base: &str, _key_bytes: &[u8]) -> anyhow::Result<bool> {
	anyhow::bail!("Gitea/Forgejo API does not expose SSH host keys")
}

/// Compare a raw key blob against a base64-encoded OpenSSH public key string.
///
/// The GitHub API returns keys as bare base64 blobs (no key-type prefix,
/// no comment).  We decode and compare byte-for-byte.
fn openssh_blob_matches(openssh_b64: &str, key_bytes: &[u8]) -> bool {
	match BASE64.decode(openssh_b64.trim()) {
		Ok(decoded) => decoded == key_bytes,
		Err(_)      => false,
	}
}

// ── known_hosts ───────────────────────────────────────────────────────────────

#[derive(Debug)]
enum KnownHostsResult {
	Match,
	Changed,
	NotFound,
}

fn known_hosts_path() -> PathBuf {
	let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
	PathBuf::from(home).join(".ssh").join("known_hosts")
}

/// Check `~/.ssh/known_hosts` for an entry matching `host`.
fn known_hosts_lookup(host: &str, key_type: &str, key_bytes: &[u8]) -> KnownHostsResult {
	let path = known_hosts_path();
	let Ok(file) = std::fs::File::open(&path) else {
		return KnownHostsResult::NotFound;
	};

	let mut found_host = false;

	for line in std::io::BufReader::new(file).lines().filter_map(|l| l.ok()) {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') {
			continue;
		}
		// Skip @cert-authority / @revoked markers.
		if line.starts_with('@') {
			continue;
		}

		let parts: Vec<&str> = line.splitn(3, ' ').collect();
		if parts.len() < 3 {
			continue;
		}
		let (pattern, entry_type, key_b64) = (parts[0], parts[1], parts[2]);

		if !host_matches_pattern(host, pattern) {
			continue;
		}

		// This entry is for our host.
		found_host = true;

		// Key type must match.
		if entry_type != key_type {
			continue;
		}

		// Decode the key blob and compare.
		let Ok(entry_bytes) = BASE64.decode(key_b64.trim()) else { continue; };
		if entry_bytes == key_bytes {
			return KnownHostsResult::Match;
		} else {
			return KnownHostsResult::Changed;
		}
	}

	if found_host {
		// We found entries for this host but none with the right key type.
		// Treat as Changed to be conservative.
		KnownHostsResult::Changed
	} else {
		KnownHostsResult::NotFound
	}
}

/// Match a hostname against a known_hosts pattern (plain, wildcard, or hashed).
fn host_matches_pattern(host: &str, pattern: &str) -> bool {
	// Hashed hostname: |1|<salt_b64>|<hash_b64>
	if pattern.starts_with("|1|") {
		return hashed_matches(host, pattern);
	}

	// Comma-separated list of plain patterns
	for p in pattern.split(',') {
		let p = p.trim();
		// [host]:port form
		let plain = if let Some(inner) = p.strip_prefix('[') {
			inner.split(']').next().unwrap_or("")
		} else {
			p
		};
		if wildcard_match(host, plain) {
			return true;
		}
	}
	false
}

/// Verify `|1|salt|hash` known_hosts entry using HMAC-SHA1.
fn hashed_matches(host: &str, pattern: &str) -> bool {
	// pattern = |1|<salt_b64>|<hash_b64>
	let stripped = pattern.trim_start_matches('|');
	let mut parts = stripped.splitn(3, '|');
	let version = parts.next().unwrap_or("");
	let salt_b64 = parts.next().unwrap_or("");
	let hash_b64 = parts.next().unwrap_or("");

	if version != "1" {
		return false;
	}
	let Ok(salt) = BASE64.decode(salt_b64) else { return false; };
	let Ok(expected) = BASE64.decode(hash_b64) else { return false; };

	let Ok(mut mac) = HmacSha1::new_from_slice(&salt) else { return false; };
	mac.update(host.as_bytes());
	let result = mac.finalize().into_bytes();

	// Constant-time compare
	result.as_slice() == expected.as_slice()
}

/// Minimal wildcard matching (* matches anything in one label, ? one char).
fn wildcard_match(host: &str, pattern: &str) -> bool {
	if pattern == "*" {
		return true;
	}
	if pattern.contains('*') {
		// Simple glob: only support leading "*." prefix
		if let Some(suffix) = pattern.strip_prefix("*.") {
			return host.ends_with(&format!(".{}", suffix)) || host == suffix;
		}
	}
	host.eq_ignore_ascii_case(pattern)
}

/// Append a new entry to `~/.ssh/known_hosts`.
fn append_known_host(host: &str, key_type: &str, key_bytes: &[u8]) -> anyhow::Result<()> {
	let path = known_hosts_path();
	// Ensure the .ssh directory exists.
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}

	let key_b64 = BASE64.encode(key_bytes);
	let line = format!("{} {} {}\n", host, key_type, key_b64);

	let mut file = std::fs::OpenOptions::new()
		.create(true)
		.append(true)
		.open(&path)?;
	file.write_all(line.as_bytes())?;
	Ok(())
}

// ── SSHFP ─────────────────────────────────────────────────────────────────────

/// Check whether the presented key matches any SSHFP record.
fn sshfp_matches(
	algo: u8,
	sha1_fp:   Option<&[u8]>,
	sha256_fp: Option<&[u8]>,
	records:   &[SshfpRecord],
) -> bool {
	for rec in records {
		if rec.algorithm != algo {
			continue;
		}
		let fp_match = match rec.fp_type {
			1 => sha1_fp.map(|f| f == rec.fingerprint.as_slice()).unwrap_or(false),
			2 => sha256_fp.map(|f| f == rec.fingerprint.as_slice()).unwrap_or(false),
			_ => false,
		};
		if fp_match {
			return true;
		}
	}
	false
}

// ── Key type helpers ──────────────────────────────────────────────────────────

pub fn key_type_str(key_type: SshHostKeyType) -> Option<&'static str> {
	match key_type {
		SshHostKeyType::Rsa              => Some("ssh-rsa"),
		SshHostKeyType::Dss              => Some("ssh-dss"),
		SshHostKeyType::Ecdsa256 => Some("ecdsa-sha2-nistp256"),
		SshHostKeyType::Ecdsa384 => Some("ecdsa-sha2-nistp384"),
		SshHostKeyType::Ecdsa384 => Some("ecdsa-sha2-nistp521"),
		SshHostKeyType::Ed255219          => Some("ssh-ed25519"),
		_                             => None,
	}
}

fn key_type_to_sshfp_algo(key_type: SshHostKeyType) -> Option<u8> {
	match key_type {
		SshHostKeyType::Rsa               => Some(1),
		SshHostKeyType::Dss               => Some(2),
		SshHostKeyType::Ecdsa256 |
		SshHostKeyType::Ecdsa384 |
		SshHostKeyType::Ecdsa521 => Some(3),
		SshHostKeyType::Ed255219           => Some(4),
		_                              => None,
	}
}
