use anyhow::{Context, Result};
use git2::{AutotagOption, FetchOptions, RemoteCallbacks, Repository, ResetType};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, RwLock};

use crate::{config::{Config, PhotoDir}, gallery};
use crate::gallery::ImageEntry;

const DEBOUNCE: Duration = Duration::from_millis(500);

// Fallback poll interval. Catches changes the OS-level watcher misses:
//   - New subdirectories added under a watched root on kqueue/FreeBSD.
//   - Network-mounted volumes whose kernel driver doesn't emit events.
//
// Override at runtime: GALLERY_POLL_SECS=60 ./photo-gallery
// Disable entirely:    GALLERY_POLL_SECS=0  ./photo-gallery
const DEFAULT_POLL_SECS: u64 = 30;

pub type GalleryMap = Arc<RwLock<HashMap<String, Vec<ImageEntry>>>>;

pub fn spawn(config: Arc<Config>, gallery_images: GalleryMap) {
    tokio::spawn(async move {
        if let Err(e) = run(config, gallery_images).await {
            tracing::error!("filesystem watcher exited with error: {e:#}");
        }
    });
}

// ── Git sync ──────────────────────────────────────────────────────────────────

/// Synchronise a git-tracked photo directory before scanning.
///
/// Uses `git2` (libgit2) directly — no dependency on `git` being on `$PATH`.
///
/// Steps:
///   1. Open the repository at `dir`.
///   2. Fetch from `origin` (the configured remote, or the first remote found).
///   3. Compare `HEAD` to `FETCH_HEAD` (the tip of the fetched branch).
///      • If identical and `!force` → nothing to do, return `false`.
///      • If different or `force`:
///          - `force = true`  → hard-reset `HEAD` to `FETCH_HEAD`
///            (discards all local changes; always matches remote).
///          - `force = false` → fast-forward `HEAD` to `FETCH_HEAD`
///            (only succeeds when `HEAD` is a direct ancestor; safe).
///
/// Credentials: tries SSH agent first, then falls back to the default SSH
/// key pair (`~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, etc.) via
/// `ssh_key_from_agent` / `ssh_key`. For HTTPS repos, credential helpers
/// configured in the system git config are used transparently by libgit2.
///
/// Returns `true` when new commits were pulled (gallery should rescan),
/// `false` when nothing changed or on any error (scan proceeds with
/// whatever is on disk regardless).
async fn git_sync(dir: &Path, force: bool, ssh_key: Option<&Path>) -> bool {
    let dir = dir.to_path_buf();
    let ssh_key = ssh_key.map(|p| p.to_path_buf());
    tokio::task::spawn_blocking(move || git_sync_blocking(&dir, force, ssh_key.as_deref()))
        .await
        .unwrap_or(false)
}

fn git_sync_blocking(dir: &Path, force: bool, ssh_key: Option<&Path>) -> bool {
    // ── Open repository ───────────────────────────────────────────────────────
    // discover() walks up the directory tree to find the .git folder,
    // so this works whether dir is the repo root or any subdirectory within it.
    let repo = match Repository::discover(dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), "git: failed to open repository: {e}");
            return false;
        }
    };

    // ── Resolve the remote name ───────────────────────────────────────────────
    // Prefer "origin"; fall back to the first configured remote.
    let remote_name = {
        let remotes = match repo.remotes() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(dir = %dir.display(), "git: failed to list remotes: {e}");
                return false;
            }
        };

        if remotes.iter().flatten().any(|n| n == "origin") {
            "origin".to_string()
        } else {
            match remotes.iter().flatten().next() {
                Some(n) => n.to_string(),
                None => {
                    tracing::warn!(dir = %dir.display(), "git: no remotes configured");
                    return false;
                }
            }
        }
    };

    // ── Fetch ─────────────────────────────────────────────────────────────────
    // Build callbacks that try SSH agent first, then fall back to the default
    // SSH key files.  This covers the most common deployment scenarios without
    // requiring credentials to be embedded in the config file.
    let mut callbacks = RemoteCallbacks::new();
    let ssh_key = ssh_key.map(|p| p.to_path_buf());
    callbacks.credentials(move |_url, username_from_url, allowed| {
        let username = username_from_url.unwrap_or("git");

        // 1. Explicit key from config — tried first when provided.
        if allowed.is_ssh_key() {
            if let Some(ref key_path) = ssh_key {
                let pub_path = key_path.with_extension(
                    format!("{}.pub", key_path.extension()
                        .and_then(|e| e.to_str()).unwrap_or(""))
                    .trim_start_matches('.')
                );
                // Use the .pub sidecar if it exists; otherwise pass None and
                // let libgit2 derive the public key from the private key.
                let pub_opt = if pub_path.exists() { Some(pub_path.as_path()) } else { None };
                if let Ok(cred) = git2::Cred::ssh_key(username, pub_opt, key_path, None) {
                    return Ok(cred);
                }
            }
        }

        // 2. SSH agent (covers key-based auth forwarded via ssh-agent).
        if allowed.is_ssh_key() {
            if let Ok(cred) = git2::Cred::ssh_key_from_agent(username) {
                return Ok(cred);
            }
        }

        // 3. Default key files in ~/.ssh/.
        if allowed.is_ssh_key() {
            let home = std::env::var("HOME").unwrap_or_default();
            for key_name in &["id_ed25519", "id_rsa", "id_ecdsa"] {
                let private = PathBuf::from(&home).join(".ssh").join(key_name);
                let public  = PathBuf::from(&home).join(".ssh").join(format!("{key_name}.pub"));
                if private.exists() {
                    if let Ok(cred) = git2::Cred::ssh_key(
                        username,
                        Some(&public),
                        &private,
                        None,
                    ) {
                        return Ok(cred);
                    }
                }
            }
        }

        // 4. Default credentials (picks up credential helpers for HTTPS).
        git2::Cred::default()
    });

    let mut fetch_opts = FetchOptions::new();
    fetch_opts.remote_callbacks(callbacks);
    fetch_opts.download_tags(AutotagOption::Unspecified);

    let mut remote = match repo.find_remote(&remote_name) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), remote = %remote_name, "git: remote not found: {e}");
            return false;
        }
    };

    // Fetch all branches tracked by the remote.
    if let Err(e) = remote.fetch(&[] as &[&str], Some(&mut fetch_opts), None) {
        tracing::warn!(dir = %dir.display(), "git fetch failed: {e}");
        return false;
    }

    // ── Resolve HEAD and FETCH_HEAD ───────────────────────────────────────────
    let head_oid = match repo.head().and_then(|r| r.peel_to_commit()) {
        Ok(c) => c.id(),
        Err(e) => {
            tracing::warn!(dir = %dir.display(), "git: cannot resolve HEAD: {e}");
            return false;
        }
    };

    let fetch_head_oid = match repo.find_reference("FETCH_HEAD").and_then(|r| r.peel_to_commit()) {
        Ok(c) => c.id(),
        Err(e) => {
            tracing::warn!(dir = %dir.display(), "git: cannot resolve FETCH_HEAD: {e}");
            return false;
        }
    };

    if head_oid == fetch_head_oid && !force {
        tracing::debug!(dir = %dir.display(), "git: already up to date");
        return false;
    }

    // ── Apply changes ─────────────────────────────────────────────────────────
    let fetch_head_commit = match repo.find_commit(fetch_head_oid) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), "git: cannot find FETCH_HEAD commit: {e}");
            return false;
        }
    };

    if force {
        // Hard reset: discard all local changes and set HEAD to FETCH_HEAD.
        let obj = fetch_head_commit.as_object();
        match repo.reset(obj, ResetType::Hard, None) {
            Ok(()) => {
                tracing::info!(
                    dir = %dir.display(),
                    commit = %fetch_head_oid,
                    "git force-reset to FETCH_HEAD"
                );
                true
            }
            Err(e) => {
                tracing::warn!(dir = %dir.display(), "git reset --hard failed: {e}");
                false
            }
        }
    } else {
        // Fast-forward: only advance HEAD if it is a direct ancestor.
        // This is equivalent to `git merge --ff-only FETCH_HEAD`.
        let fetch_head_annotated = match repo.find_annotated_commit(fetch_head_oid) {
            Ok(ac) => ac,
            Err(e) => {
                tracing::warn!(dir = %dir.display(), "git: cannot build annotated FETCH_HEAD: {e}");
                return false;
            }
        };

        let (analysis, _pref) = match repo.merge_analysis(&[&fetch_head_annotated]) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(dir = %dir.display(), "git merge analysis failed: {e}");
                return false;
            }
        };

        if analysis.is_up_to_date() {
            tracing::debug!(dir = %dir.display(), "git: already up to date");
            return false;
        }

        if !analysis.is_fast_forward() {
            tracing::warn!(
                dir = %dir.display(),
                "git: fast-forward not possible (history diverged); \
                 use git_force_pull: true to override"
            );
            return false;
        }

        // Move HEAD ref to FETCH_HEAD.
        let refname = match repo.head() {
            Ok(r) => r.name().unwrap_or("HEAD").to_string(),
            Err(_) => "HEAD".to_string(),
        };

        match repo.find_reference(&refname)
            .and_then(|mut r| {
                r.set_target(
                    fetch_head_oid,
                    &format!("fast-forward to {fetch_head_oid}"),
                )?;
                Ok(())
            })
            .and_then(|()| {
                repo.set_head(&refname)?;
                repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
            })
        {
            Ok(()) => {
                tracing::info!(
                    dir = %dir.display(),
                    commit = %fetch_head_oid,
                    "git fast-forward to FETCH_HEAD"
                );
                true
            }
            Err(e) => {
                tracing::warn!(dir = %dir.display(), "git fast-forward failed: {e}");
                false
            }
        }
    }
}

// ── Watcher ───────────────────────────────────────────────────────────────────

async fn run(config: Arc<Config>, gallery_images: GalleryMap) -> Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel::<notify::Result<Event>>();

    // Build mapping: canonical dir → gallery slugs that contain it.
    let mut dir_to_slugs: HashMap<PathBuf, Vec<String>> = HashMap::new();
    for gallery in &config.galleries {
        for photo_dir in &gallery.photo_dirs {
            match photo_dir.dir.canonicalize() {
                Ok(canonical) => {
                    dir_to_slugs
                        .entry(canonical)
                        .or_default()
                        .push(gallery.url.clone());
                }
                Err(e) => {
                    tracing::warn!(
                        dir = %photo_dir.dir.display(),
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

    let tx2 = tx.clone();
    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |res| { let _ = tx2.send(res); })
        .context("creating filesystem watcher")?;

    for dir in dir_to_slugs.keys() {
        if let Err(e) = watcher.watch(dir, RecursiveMode::Recursive) {
            tracing::warn!(dir = %dir.display(), "could not watch directory: {e}");
        } else {
            tracing::debug!(dir = %dir.display(), "watching for changes");
        }
    }

    let poll_secs = std::env::var("GALLERY_POLL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_POLL_SECS);

    let polling_enabled = poll_secs > 0;
    let effective_interval = if polling_enabled {
        Duration::from_secs(poll_secs)
    } else {
        Duration::from_secs(u64::MAX / 2)
    };

    let mut poll_tick = tokio::time::interval(effective_interval);
    poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    poll_tick.tick().await;

    let all_slugs: Vec<String> = config.galleries.iter().map(|g| g.url.clone()).collect();

    // Precompute git-enabled dirs per slug to avoid re-scanning on every tick.
    let git_dirs: HashMap<String, Vec<PhotoDir>> = config.galleries.iter()
        .map(|g| {
            let dirs = g.photo_dirs.iter().filter(|d| d.git).cloned().collect();
            (g.url.clone(), dirs)
        })
        .collect();

    tracing::info!(
        dirs = dir_to_slugs.len(),
        poll_secs = if polling_enabled { poll_secs } else { 0 },
        "filesystem watcher active"
    );

    let mut pending_slugs: HashSet<String> = HashSet::new();

    loop {
        tokio::select! {
            event = rx.recv() => {
                handle_event(event, &dir_to_slugs, &mut pending_slugs);
                loop {
                    match tokio::time::timeout(DEBOUNCE, rx.recv()).await {
                        Ok(Some(ev)) => handle_event(Some(ev), &dir_to_slugs, &mut pending_slugs),
                        Ok(None) | Err(_) => break,
                    }
                }
            }

            _ = poll_tick.tick() => {
                tracing::debug!("poll tick: queuing rescan of all galleries");
                pending_slugs.extend(all_slugs.iter().cloned());
            }
        }

        if pending_slugs.is_empty() {
            continue;
        }

        for slug in pending_slugs.drain() {
            let Some(gallery_cfg) = config.galleries.iter().find(|g| g.url == slug) else {
                continue;
            };

            // Git sync runs before scan_gallery so pulled files are included.
            if let Some(dirs) = git_dirs.get(&slug) {
                for photo_dir in dirs {
                    git_sync(&photo_dir.dir, photo_dir.git_force_pull, photo_dir.git_ssh_key.as_deref()).await;
                }
            }

            match gallery::scan_gallery(gallery_cfg) {
                Ok(images) => {
                    let mut map = gallery_images.write().await;
                    let old_count = map.get(&slug).map(|v| v.len()).unwrap_or(0);
                    let new_count = images.len();
                    map.insert(slug.clone(), images);

                    if new_count != old_count {
                        tracing::info!(
                            gallery = %slug,
                            old = old_count,
                            new = new_count,
                            delta = new_count as i64 - old_count as i64,
                            "hot-reloaded gallery"
                        );
                    } else {
                        tracing::trace!(gallery = %slug, count = new_count, "poll rescan: no change");
                    }
                }
                Err(e) => {
                    tracing::error!(gallery = %slug, "rescan failed: {e:#}");
                }
            }
        }
    }
}

fn handle_event(
    event: Option<notify::Result<Event>>,
    dir_to_slugs: &HashMap<PathBuf, Vec<String>>,
    pending: &mut HashSet<String>,
) {
    let Some(Ok(ev)) = event else { return };

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
