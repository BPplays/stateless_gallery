use anyhow::{Context, Result};
use bytes::Bytes;
use image::imageops::FilterType;
use img_parts::jpeg::{Jpeg, JpegSegment};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::config::ThumbnailConfig;

// ─── Extension helpers ───────────────────────────────────────────────────────

fn ext(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
}

pub fn is_jpeg(path: &Path) -> bool {
    matches!(ext(path).as_deref(), Some("jpg") | Some("jpeg"))
}

pub fn is_avif(path: &Path) -> bool {
    matches!(ext(path).as_deref(), Some("avif"))
}

/// Returns `true` for every image format the `image` crate can decode.
pub fn is_supported_image(path: &Path) -> bool {
    matches!(
        ext(path).as_deref(),
        Some("jpg")
            | Some("jpeg")
            | Some("png")
            | Some("webp")
            | Some("gif")
            | Some("bmp")
            | Some("tiff")
            | Some("tif")
            | Some("avif") // decoded only if the "avif" feature is enabled
    )
}

// ─── Cache key ───────────────────────────────────────────────────────────────

/// Returns a hex-encoded SHA-256 that encodes the image path + every config
/// parameter that influences thumbnail appearance.  Any config change
/// automatically invalidates the cache.
pub fn cache_key(image_path: &Path, cfg: &ThumbnailConfig) -> String {
    let mut h = Sha256::new();
    h.update(image_path.to_string_lossy().as_bytes());
    h.update(cfg.max_size.to_le_bytes());
    h.update([cfg.quality]);
    h.update([cfg.preserve_gainmaps as u8]);
    hex::encode(h.finalize())
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Returns the path of a (potentially cached) thumbnail for `image_path`.
///
/// | Condition                                   | Returns            |
/// |---------------------------------------------|--------------------|
/// | `thumbnails.enabled = false`                | `Ok(None)` → serve original |
/// | AVIF + `preserve_gainmaps = true`           | `Ok(None)` → serve original |
/// | Thumbnail already in cache                  | `Ok(Some(cached))` |
/// | Thumbnail generated and written to cache    | `Ok(Some(cached))` |
/// | Decoding / encoding error                   | `Err(...)`         |
pub fn get_or_create_thumbnail(
    image_path: &Path,
    cache_dir: &Path,
    cfg: &ThumbnailConfig,
) -> Result<Option<PathBuf>> {
    // ── No thumbnails requested ──────────────────────────────────────────────
    if !cfg.enabled {
        return Ok(None);
    }

    // ── AVIF gainmap passthrough ─────────────────────────────────────────────
    // AVIF gainmaps live inside the ISOBMFF container as auxiliary image items.
    // Re-encoding through the `image` crate would silently drop them, so we
    // serve the original unchanged when preservation is requested.
    if is_avif(image_path) && cfg.preserve_gainmaps {
        return Ok(None);
    }

    // ── Cache hit ────────────────────────────────────────────────────────────
    let cache_path = cache_dir.join(format!("{}.jpg", cache_key(image_path, cfg)));
    if cache_path.exists() {
        return Ok(Some(cache_path));
    }

    // ── Load & resize ────────────────────────────────────────────────────────
    let original_bytes =
        std::fs::read(image_path).with_context(|| format!("reading {}", image_path.display()))?;

    let img = image::load_from_memory(&original_bytes)
        .with_context(|| format!("decoding {}", image_path.display()))?;

    let (ow, oh) = (img.width(), img.height());
    let max = cfg.max_size;

    // Compute thumbnail dimensions, preserving aspect ratio.
    let (nw, nh) = if ow == 0 || oh == 0 {
        (max, max)
    } else if ow >= oh {
        (max, ((oh as u64 * max as u64) / ow as u64).max(1) as u32)
    } else {
        (((ow as u64 * max as u64) / oh as u64).max(1) as u32, max)
    };

    // If the image is already at or below the thumbnail size there is nothing
    // to do; encode it as JPEG and proceed to the metadata step.
    let resized = if ow <= nw && oh <= nh {
        img
    } else {
        img.resize(nw, nh, FilterType::Lanczos3)
    };

    // ── Encode thumbnail ─────────────────────────────────────────────────────
    let mut thumb_bytes: Vec<u8> = Vec::new();
    {
        let mut cursor = Cursor::new(&mut thumb_bytes);
        let enc =
            image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, cfg.quality.clamp(1, 100));
        resized
            .write_with_encoder(enc)
            .context("encoding thumbnail as JPEG")?;
    }

    // ── JPEG gainmap preservation ─────────────────────────────────────────────
    // For JPEG sources, transplant **all** APP* segments (0xE0–0xEF) from the
    // original into the resized JPEG.  This preserves:
    //   • EXIF (APP1)
    //   • ICC colour profile (APP2)
    //   • MPF / Multi-Picture Format used by Apple's HDR gainmaps (APP2)
    //   • ISO 21496-1 Ultra HDR gainmap (APP2)
    //   • Any other vendor metadata segments
    //
    // The image content (DQT / SOF / DHT / SOS / …) always comes from the
    // freshly resized thumbnail; only the metadata rides along.
    let final_bytes = if is_jpeg(image_path) && cfg.preserve_gainmaps {
        // Keep a clone so we can fall back to the bare thumbnail if the
        // segment transplant fails (rather than losing the image entirely).
        let bare = thumb_bytes.clone();
        match transplant_jpeg_app_segments(original_bytes, thumb_bytes) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    path = %image_path.display(),
                    "gainmap APP-segment transplant failed ({e}); \
                     saving thumbnail without metadata"
                );
                bare
            }
        }
    } else {
        thumb_bytes
    };

    // ── Write cache ───────────────────────────────────────────────────────────
    std::fs::create_dir_all(cache_dir).context("creating cache directory")?;
    std::fs::write(&cache_path, &final_bytes)
        .with_context(|| format!("writing thumbnail {}", cache_path.display()))?;

    Ok(Some(cache_path))
}

// ─── JPEG APP-segment transplant ─────────────────────────────────────────────

/// Replaces the APP* segments in `dst_jpeg` with those from `src_jpeg`.
///
/// Steps:
/// 1. Parse both JPEGs with `img-parts`.
/// 2. Collect all APP* segments (markers 0xE0–0xEF) from the source.
/// 3. Strip all APP* segments from the thumbnail.
/// 4. Prepend the source APP* segments to the thumbnail's segment list so that
///    they appear right after the SOI — the standard location required by the
///    JPEG spec.
/// 5. Re-serialise.
fn transplant_jpeg_app_segments(src_bytes: Vec<u8>, dst_bytes: Vec<u8>) -> Result<Vec<u8>> {
    let src =
        Jpeg::from_bytes(Bytes::from(src_bytes)).context("img-parts: parsing source JPEG")?;

    let mut dst =
        Jpeg::from_bytes(Bytes::from(dst_bytes)).context("img-parts: parsing thumbnail JPEG")?;

    // Collect APP* segments from the original, in document order.
    let app_segments: Vec<JpegSegment> = src
        .segments()
        .iter()
        .filter(|s| matches!(s.marker(), 0xE0..=0xEF))
        .cloned()
        .collect();

    // Grab the non-APP* body from the thumbnail (quantisation tables, Huffman
    // tables, scan data, …).
    let body: Vec<JpegSegment> = dst
        .segments()
        .iter()
        .filter(|s| !matches!(s.marker(), 0xE0..=0xEF))
        .cloned()
        .collect();

    // Assemble: [original APP* segments] + [thumbnail body].
    let mut merged = app_segments;
    merged.extend(body);
    *dst.segments_mut() = merged;

    let out: Bytes = dst.encoder().bytes();
    Ok(out.to_vec())
}
