use anyhow::Result;
use std::path::PathBuf;
use walkdir::WalkDir;

use crate::{config::GalleryConfig, thumbnail};

/// A single discovered image file.
#[derive(Clone, Debug)]
pub struct ImageEntry {
    pub path: PathBuf,
    pub filename: String,
}

/// Recursively scan all `photo_dirs` in a gallery config and return the
/// sorted list of supported image files.
pub fn scan_gallery(gallery: &GalleryConfig) -> Result<Vec<ImageEntry>> {
    let mut images: Vec<ImageEntry> = Vec::new();

    for photo_dir in &gallery.photo_dirs {
        let dir = &photo_dir.dir;

        if !dir.exists() {
            tracing::warn!(
                gallery = %gallery.url,
                dir = %dir.display(),
                "photo_dir does not exist, skipping"
            );
            continue;
        }

        let before = images.len();

        for entry in WalkDir::new(dir)
            .follow_links(true)
            .sort_by(|a, b| a.file_name().cmp(b.file_name()))
            .into_iter()
            .filter_map(|e| {
                e.map_err(|err| tracing::warn!("walkdir error: {err}"))
                    .ok()
            })
        {
            if entry.file_type().is_file() {
                let path = entry.into_path();
                if !thumbnail::is_thumb_path(&path) {
                    let filename = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    images.push(ImageEntry { path, filename });
                }
            }
        }

        tracing::debug!(
            gallery = %gallery.url,
            dir = %dir.display(),
            found = images.len() - before,
            "scanned directory"
        );
    }

    tracing::info!(
        gallery = %gallery.url,
        count = images.len(),
        "scan complete"
    );

    Ok(images)
}
