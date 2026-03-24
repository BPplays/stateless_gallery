use serde::{Deserialize, Deserializer};
use std::path::PathBuf;

/// Top-level gallery configuration (YAML).
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    /// One or more named galleries, each served under its own URL slug.
    pub galleries: Vec<GalleryConfig>,

    /// Directory used to cache generated thumbnails.
    pub cache_dir: PathBuf,

    /// TCP address to listen on.
    #[serde(default = "default_bind")]
    pub bind: String,

    /// Thumbnail generation settings (shared across all galleries).
    #[serde(default)]
    pub thumbnails: ThumbnailConfig,

    #[serde(default)]
    pub network: NetworkConfig,
}

fn default_bind() -> String {
    "[::1]:8080".into()
}

/// Per-gallery configuration.
#[derive(Deserialize, Clone, Debug)]
pub struct GalleryConfig {
    /// Human-readable title shown in the browser.
    pub name: String,

    /// URL slug under which this gallery is served.
    pub url: String,

    /// Optional access secret.
    #[serde(default)]
    pub secret: String,

    /// Directories scanned recursively for images.
    pub photo_dirs: Vec<PhotoDir>,
}

impl GalleryConfig {
    pub fn requires_secret(&self) -> bool {
        !self.secret.is_empty()
    }

    pub fn secret_matches(&self, candidate: &str) -> bool {
        let a = self.secret.as_bytes();
        let b = candidate.as_bytes();
        if a.len() != b.len() {
            return false;
        }
        let mismatch = a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y));
        mismatch == 0
    }
}

/// A photo directory entry.
///
/// Accepts two YAML forms:
///
/// Plain path (backward-compatible):
/// ```yaml
/// photo_dirs:
///   - /home/user/Pictures/public
/// ```
///
/// Object form with optional git tracking:
/// ```yaml
/// photo_dirs:
///   - dir: /home/user/Pictures/public
///   - dir: /home/user/Pictures/vacation
///     git: true            # fetch on every scan; pull if new commits found
///     git_force_pull: true # force-reset to remote HEAD (discards local changes)
///     git_ssh_key: /home/user/.ssh/deploy_key  # optional: explicit private key
/// ```
#[derive(Clone, Debug)]
pub struct PhotoDir {
    /// The filesystem path to scan.
    pub dir: PathBuf,

    /// If `true`, fetch from the configured remote before every scan and
    /// merge (or reset) if new commits are found.
    pub git: bool,

    /// If `true` (implies `git: true`), force-reset to the remote HEAD on
    /// every scan, discarding any local modifications.
    pub git_force_pull: bool,

    /// Optional path to a specific SSH private key file to use when
    /// authenticating with the remote.  When absent the credential callback
    /// tries the SSH agent and the standard key files in `~/.ssh/` instead.
    ///
    /// The matching public key is inferred by appending `.pub`; if that file
    /// does not exist libgit2 will attempt to derive it from the private key.
    pub git_ssh_key: Option<PathBuf>,

    pub git_ssh_add_new_key: bool,
}

/// Private helper enum used only for deserialization.
#[derive(Deserialize)]
#[serde(untagged)]
enum PhotoDirDe {
    /// `- /some/path`
    Path(PathBuf),
    /// Object form with all optional git fields.
    Full {
        dir: PathBuf,
        #[serde(default)]
        git: bool,
        #[serde(default)]
        git_force_pull: bool,
        #[serde(default)]
        git_ssh_key: Option<PathBuf>,
    },
}

impl<'de> Deserialize<'de> for PhotoDir {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match PhotoDirDe::deserialize(deserializer)? {
            PhotoDirDe::Path(dir) => Ok(PhotoDir {
                dir,
                git: false,
                git_force_pull: false,
                git_ssh_key: None,
            }),
            PhotoDirDe::Full { dir, git, git_force_pull, git_ssh_key } => Ok(PhotoDir {
                dir,
                git: git || git_force_pull,
                git_force_pull,
                git_ssh_key,
            }),
        }
    }
}

/// Controls how (and whether) thumbnails are generated.
#[derive(Deserialize, Clone, Debug)]
pub struct ThumbnailConfig {
    #[serde(default = "bool_true")]
    pub enabled: bool,
    #[serde(default = "default_max_size")]
    pub max_size: u32,
    #[serde(default = "default_quality")]
    pub quality: u8,
    #[serde(default = "bool_true")]
    pub preserve_gainmaps: bool,
}

fn bool_true() -> bool { true }
fn default_max_size() -> u32 { 640 }
fn default_quality() -> u8 { 90 }

impl Default for ThumbnailConfig {
    fn default() -> Self {
        Self { enabled: true, max_size: 640, quality: 90, preserve_gainmaps: true }
    }
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct NetworkConfig {
    #[serde(default)]
    pub dns: Vec<DnsGroup>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct DnsGroup {
    pub group: String, // "doh", "dot", "dns"
    pub servers: Vec<DnsServer>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct DnsServer {
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(rename = "type")]
    pub kind: String, // doh | dot | dns
}

