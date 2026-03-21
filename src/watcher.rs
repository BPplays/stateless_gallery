use anyhow::{Context, Result};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, RwLock};

use crate::{config::Config, gallery};
use crate::gallery::ImageEntry;

// How long after the last filesystem event to wait before rescanning.
// Batches rapid bursts (rsync, cp -r, Lightroom export …) into one rescan.
const DEBOUNCE: Duration = Duration::from_millis(500);

pub type GalleryMap = Arc<RwLock<HashMap<String, Vec<ImageEntry>>>>;

/// Spawn a background task that watches every `photo_dir` declared in the
/// config and hot-reloads the affected gallery's image list when anything
/// changes.
///
/// Returns immediately; the watcher runs for the lifetime of the process.
/// On error (e.g. a directory is unmounted) it logs a warning and stops
/// watching that path, but does not crash the server.
pub fn spawn(config: Arc<Config>, gallery_images: GalleryMap) {
    tokio::spawn(async move {
        if let Err(e) = run(config, gallery_images).await {
            tracing::error!("filesystem watcher exited with error: {e:#}");
        }
    });
}

async fn run(config: Arc<Config>, gallery_images: GalleryMap) -> Result<()> {
    // ── Channel between the notify callback (sync) and our async task ────────
    let (tx, mut rx) = mpsc::unbounded_channel::<notify::Result<Event>>();

    // ── Build mapping:  canonical dir  →  gallery slugs that contain it ──────
    // Used to translate a changed path back to the gallery(s) to rescan.
    let mut dir_to_slugs: HashMap<PathBuf, Vec<String>> = HashMap::new();
    for gallery in &config.galleries {
        for dir in &gallery.photo_dirs {
            match dir.canonicalize() {
                Ok(canonical) => {
                    dir_to_slugs
                        .entry(canonical)
                        .or_default()
                        .push(gallery.url.clone());
                }
                Err(e) => {
                    tracing::warn!(
                        dir = %dir.display(),
                        "cannot canonicalize photo_dir (watcher will skip it): {e}"
                    );
                }
            }
        }
    }

    if dir_to_slugs.is_empty() {
        tracing::warn!("no watchable directories found; hot-reload disabled");
        return Ok(());
    }

    // ── Start the notify watcher ──────────────────────────────────────────────
    let tx2 = tx.clone();
    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |res| {
            let _ = tx2.send(res);
        })
        .context("creating filesystem watcher")?;

    for dir in dir_to_slugs.keys() {
        if let Err(e) = watcher.watch(dir, RecursiveMode::Recursive) {
            tracing::warn!(dir = %dir.display(), "could not watch directory: {e}");
        } else {
            tracing::debug!(dir = %dir.display(), "watching for changes");
        }
    }

    tracing::info!(
        dirs = dir_to_slugs.len(),
        "filesystem watcher active"
    );

    // ── Event loop with debounce ───────────────────────────────────────────────
    let mut pending_slugs: HashSet<String> = HashSet::new();

    loop {
        // Block until there is at least one event.
        let first = rx.recv().await;
        handle_event(first, &dir_to_slugs, &mut pending_slugs);

        // Drain the channel for `DEBOUNCE` after the *last* event so that a
        // burst of changes (e.g. a large import) results in only one rescan.
        loop {
            match tokio::time::timeout(DEBOUNCE, rx.recv()).await {
                Ok(Some(ev)) => handle_event(Some(ev), &dir_to_slugs, &mut pending_slugs),
                // Timeout (quiet period reached) or channel closed → stop draining.
                Ok(None) | Err(_) => break,
            }
        }

        if pending_slugs.is_empty() {
            continue;
        }

        // Rescan every affected gallery.
        for slug in pending_slugs.drain() {
            let Some(gallery_cfg) = config.galleries.iter().find(|g| g.url == slug) else {
                continue;
            };

            match gallery::scan_gallery(gallery_cfg) {
                Ok(images) => {
                    let mut map = gallery_images.write().await;
                    let old_count = map.get(&slug).map(|v| v.len()).unwrap_or(0);
                    let new_count = images.len();
                    map.insert(slug.clone(), images);
                    tracing::info!(
                        gallery = %slug,
                        old = old_count,
                        new = new_count,
                        delta = new_count as i64 - old_count as i64,
                        "hot-reloaded gallery"
                    );
                }
                Err(e) => {
                    tracing::error!(gallery = %slug, "rescan failed: {e:#}");
                }
            }
        }
    }
}

/// Translate a raw notify event into affected gallery slugs and accumulate
/// them in `pending`.
fn handle_event(
    event: Option<notify::Result<Event>>,
    dir_to_slugs: &HashMap<PathBuf, Vec<String>>,
    pending: &mut HashSet<String>,
) {
    let Some(Ok(ev)) = event else { return };

    // Only care about events that actually change the set of image files.
    use notify::EventKind::*;
    match ev.kind {
        Create(_) | Remove(_) | Modify(_) | Rename(_) => {}
        _ => return,
    }

    for changed_path in &ev.paths {
        for (watched_dir, slugs) in dir_to_slugs {
            if changed_path.starts_with(watched_dir) {
                pending.extend(slugs.iter().cloned());
            }
        }
    }
}
