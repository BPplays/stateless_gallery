use serde::Deserialize;
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
    ///
    /// A gallery with `url: "holidays"` is reachable at:
    ///   `http://host:port/holidays`
    ///
    /// The slug must be non-empty and contain only URL-safe characters
    /// (letters, digits, hyphens, underscores).
    pub url: String,

    /// Optional access secret.
    ///
    /// When non-empty every request to this gallery **must** include
    /// `?secret=<value>` (in the index page URL *and* automatically
    /// appended to thumb/full URLs by the client-side JS).
    ///
    /// An empty string (or omitting the field) means the gallery is public.
    #[serde(default)]
    pub secret: String,

    /// Directories scanned recursively for images.
    pub photo_dirs: Vec<PathBuf>,
}

impl GalleryConfig {
    /// Returns `true` if this gallery requires a secret to access.
    pub fn requires_secret(&self) -> bool {
        !self.secret.is_empty()
    }

    /// Constant-time-ish secret comparison (avoids short-circuit on first
    /// differing byte; good enough for a URL token).
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
