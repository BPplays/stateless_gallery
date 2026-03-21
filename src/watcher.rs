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
// Batches rapid bursts (rsync, cp -r, Lightroom export ...) into one rescan.
const DEBOUNCE: Duration = Duration::from_millis(500);

// Fallback poll interval. Catches changes the OS-level watcher misses:
//   - New subdirectories added under a watched root on kqueue/FreeBSD
//     (kqueue opens fds for paths that exist at startup; it never learns
//     about directories created afterwards until we reopen them).
//   - Network-mounted volumes whose kernel driver doesn't emit events.
//   - Any other edge case where notify silently drops an event.
//
// The poll simply marks every gallery as pending so scan_gallery reruns.
// Because scan_gallery is already idempotent and cheap (it only calls
// WalkDir + a stat per file), a 30-second poll adds negligible overhead
// even for large libraries.
//
// Override at runtime: GALLERY_POLL_SECS=60 ./photo-gallery
// Disable entirely:    GALLERY_POLL_SECS=0  ./photo-gallery
const DEFAULT_POLL_SECS: u64 = 30;

pub type GalleryMap = Arc<RwLock<HashMap<String, Vec<ImageEntry>>>>;

/// Spawn a background task that watches every `photo_dir` declared in the
/// config and hot-reloads the affected gallery's image list when anything
/// changes.
///
/// Two mechanisms run concurrently in the same loop:
///   1. `notify` events  -- low-latency, OS-driven (inotify / kqueue / FSEvents)
///   2. Periodic poll    -- safety net for kqueue blind-spots and network mounts
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
    // -- Channel between the notify callback (sync) and our async task --------
    let (tx, mut rx) = mpsc::unbounded_channel::<notify::Result<Event>>();

    // -- Build mapping:  canonical dir -> gallery slugs that contain it -------
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

    // -- Start the notify watcher ---------------------------------------------
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

    // -- Poll interval --------------------------------------------------------
    // Read an optional override from the environment, falling back to the
    // compiled-in default. GALLERY_POLL_SECS=0 disables polling.
    let poll_secs = std::env::var("GALLERY_POLL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_POLL_SECS);

    let polling_enabled = poll_secs > 0;

    // When disabled, use a very long interval so the ticker arm in select!
    // is always present but never actually fires.
    let effective_interval = if polling_enabled {
        Duration::from_secs(poll_secs)
    } else {
        Duration::from_secs(u64::MAX / 2)
    };

    let mut poll_tick = tokio::time::interval(effective_interval);
    // Delay: if a tick is missed (e.g. the rescan took longer than the
    // interval) wait a full interval from when we next check rather than
    // firing immediately to "catch up".
    poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    poll_tick.tick().await; // consume the immediate first tick

    // Pre-collect all slugs so the poll arm doesn't borrow `config` inside
    // the select! each iteration.
    let all_slugs: Vec<String> = config.galleries.iter().map(|g| g.url.clone()).collect();

    tracing::info!(
        dirs = dir_to_slugs.len(),
        poll_secs = if polling_enabled { poll_secs } else { 0 },
        "filesystem watcher active"
    );

    // -- Event loop -----------------------------------------------------------
    // Both the notify channel and the poll timer feed into `pending_slugs`.
    // The drain-and-rescan block at the bottom handles both sources uniformly.
    let mut pending_slugs: HashSet<String> = HashSet::new();

    loop {
        tokio::select! {
            // -- notify event -------------------------------------------------
            // Block until at least one filesystem event arrives, then drain
            // the channel for DEBOUNCE so a burst becomes a single rescan.
            event = rx.recv() => {
                handle_event(event, &dir_to_slugs, &mut pending_slugs);

                loop {
                    match tokio::time::timeout(DEBOUNCE, rx.recv()).await {
                        Ok(Some(ev)) => handle_event(Some(ev), &dir_to_slugs, &mut pending_slugs),
                        // Quiet period reached or channel closed.
                        Ok(None) | Err(_) => break,
                    }
                }
            }

            // -- poll tick ----------------------------------------------------
            // Mark every gallery for rescan. scan_gallery + walkdir is cheap
            // and idempotent; if nothing changed the counts will match and
            // the log line will show delta = 0 at TRACE level.
            _ = poll_tick.tick() => {
                tracing::debug!("poll tick: queuing rescan of all galleries");
                pending_slugs.extend(all_slugs.iter().cloned());
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

                    // Only log at INFO when something actually changed; poll
                    // ticks that find nothing new are silent at INFO level.
                    if new_count != old_count {
                        tracing::info!(
                            gallery = %slug,
                            old = old_count,
                            new = new_count,
                            delta = new_count as i64 - old_count as i64,
                            "hot-reloaded gallery"
                        );
                    } else {
                        tracing::trace!(
                            gallery = %slug,
                            count = new_count,
                            "poll rescan: no change"
                        );
                    }
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
    use notify::EventKind;
    match ev.kind {
        EventKind::Create(_) | EventKind::Remove(_) | EventKind::Modify(_) => {}
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
