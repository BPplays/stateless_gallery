use anyhow::{Context, Result};
use git2::{
	cert::{Cert, CertHostkey},
	AutotagOption, CertificateCheckStatus, FetchOptions, RemoteCallbacks, Repository, ResetType,
};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
	collections::{HashMap, HashSet}, path::{Path, PathBuf}, sync::Arc, thread::sleep, time::Duration
};
use tokio::sync::{mpsc, RwLock};

use crate::{
	config::{Config, PhotoDir},
	dns::DnsResolver,
	gallery,
	gallery::ImageEntry,
	ssh_verify::SshVerifier,
};
use std::time::{Instant};

const DEBOUNCE: Duration = Duration::from_millis(500);

const SYNC_COOLDOWN: Duration = Duration::from_secs(29);

// Override at runtime: GALLERY_POLL_SECS=60 ./photo-gallery
// Disable entirely:    GALLERY_POLL_SECS=0  ./photo-gallery
const DEFAULT_POLL_SECS: u64 = 5;

pub type GalleryMap = Arc<RwLock<HashMap<String, Vec<ImageEntry>>>>;

pub fn spawn(config: Arc<Config>, gallery_images: GalleryMap) {
	tokio::spawn(async move {
		if let Err(e) = run(config, gallery_images).await {
			tracing::error!("filesystem watcher exited with error: {e:#}");
		}
	});
}

// ── Git sync ──────────────────────────────────────────────────────────────────

async fn git_sync(photo_dir: &PhotoDir, verifier: &Arc<SshVerifier>) -> bool {
	let photo_dir = photo_dir.clone();
	let verifier  = Arc::clone(verifier);

	tokio::task::spawn_blocking(move || {
		let handle = tokio::runtime::Handle::current();
		git_sync_blocking(&photo_dir, &verifier, &handle)
	})
	.await
	.unwrap_or(false)
}

fn git_sync_blocking(
	photo_dir: &PhotoDir,
	verifier:  &Arc<SshVerifier>,
	handle:    &tokio::runtime::Handle,
) -> bool {
	let dir   = photo_dir.dir.as_path();
	let force = photo_dir.git_force_pull;

	// discover() walks up the directory tree to find .git, so this works
	// whether dir is the repo root or a subdirectory within it.
	let repo = match Repository::discover(dir) {
		Ok(r)  => r,
		Err(e) => {
			tracing::warn!(dir = %dir.display(), "git: failed to open repository: {e}");
			return false;
		}
	};

	// Prefer "origin"; fall back to the first configured remote.
	let remote_name = {
		let remotes = match repo.remotes() {
			Ok(r)  => r,
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
				None    => {
					tracing::warn!(dir = %dir.display(), "git: no remotes configured");
					return false;
				}
			}
		}
	};

	// ── Build callbacks ───────────────────────────────────────────────────────
	let mut callbacks = RemoteCallbacks::new();

	// SSH host key verification.
	{
		let verifier       = Arc::clone(verifier);
		let add_new_key    = photo_dir.git_ssh_add_new_key;
		let handle         = handle.clone();
		callbacks.certificate_check(move |cert: &Cert<'_>, hostname| {
			let Some(hostkey) = cert.as_hostkey() else {
				// Non-SSH certificate (e.g. TLS); pass through.
				return Ok(CertificateCheckStatus::CertificateOk);
			};
			let result = handle.block_on(verifier.verify(
				hostname,
				photo_dir.git_pat.clone(),
				hostkey,
				add_new_key,
			));
			if result.is_ok() {
				Ok(CertificateCheckStatus::CertificateOk)
			} else {
				let msg = match result {
					crate::ssh_verify::VerifyResult::KeyChanged =>
						"host key has changed — possible MITM attack",
					_ => "host key verification failed",
				};
				tracing::error!(host = %hostname, "git: {msg}");
				Err(git2::Error::from_str(msg))
			}
		});
	}

	// SSH / HTTPS credential resolution.
	{
		let ssh_key = photo_dir.git_ssh_key.clone();
		callbacks.credentials(move |_url, username_from_url, allowed| {
			let username = username_from_url.unwrap_or("git");
			// tracing::info!(username = username, "cred user");

			// 1. Explicit key from config.
			if allowed.is_ssh_key() {
				// tracing::info!(
				// 	key_path = ssh_key.clone().unwrap_or(PathBuf::default()).to_string_lossy().to_string(),
				// 	"trying key from path",
				// );
				if let Some(ref key_path) = ssh_key {
					let pub_path = {
						let mut p = key_path.clone();
						let new_name = format!(
							"{}.pub",
							p.file_name().and_then(|n| n.to_str()).unwrap_or("")
						);
						p.set_file_name(new_name);
						p
					};
					let pub_opt = if pub_path.exists() { Some(pub_path.as_path()) } else { None };
					let result = git2::Cred::ssh_key(username, pub_opt, key_path, None);

					match result {
						Ok(cred) => {
							// tracing::info!(
							// 	"cred ok",
							// );
							return Ok(cred);
						}
						Err(e) => {
							tracing::info!(
								err = e.to_string(),
								"cred err",
							);
						}
					}


				}
			}

			// 2. SSH agent.
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
					let public  = PathBuf::from(&home).join(".ssh")
										.join(format!("{key_name}.pub"));
					if private.exists() {
						let pub_opt = if public.exists() { Some(public.as_path()) } else { None };
						if let Ok(cred) = git2::Cred::ssh_key(username, pub_opt, &private, None) {
							return Ok(cred);
						}
					}
				}
			}

			// 4. Default (picks up HTTPS credential helpers).
			git2::Cred::default()
		});
	}

	// ── Fetch ─────────────────────────────────────────────────────────────────
	let mut fetch_opts = FetchOptions::new();
	fetch_opts.remote_callbacks(callbacks);
	fetch_opts.download_tags(AutotagOption::Unspecified);

	let mut remote = match repo.find_remote(&remote_name) {
		Ok(r)  => r,
		Err(e) => {
			tracing::warn!(dir = %dir.display(), remote = %remote_name,
						   "git: remote not found: {e}");
			return false;
		}
	};

	if let Err(e) = remote.fetch(&[] as &[&str], Some(&mut fetch_opts), None) {
		tracing::warn!(dir = %dir.display(), "git fetch failed: {e}");
		return false;
	}

	// ── Compare HEAD ↔ FETCH_HEAD ────────────────────────────────────────────
	let head_oid = match repo.head().and_then(|r| r.peel_to_commit()) {
		Ok(c)  => c.id(),
		Err(e) => {
			tracing::warn!(dir = %dir.display(), "git: cannot resolve HEAD: {e}");
			return false;
		}
	};

	let fetch_head_oid =
		match repo.find_reference("FETCH_HEAD").and_then(|r| r.peel_to_commit()) {
			Ok(c)  => c.id(),
			Err(e) => {
				tracing::warn!(dir = %dir.display(),
							   "git: cannot resolve FETCH_HEAD: {e}");
				return false;
			}
		};

	if head_oid == fetch_head_oid && !force {
		tracing::debug!(dir = %dir.display(), "git: already up to date");
		return false;
	}

	let fetch_head_commit = match repo.find_commit(fetch_head_oid) {
		Ok(c)  => c,
		Err(e) => {
			tracing::warn!(dir = %dir.display(),
						   "git: cannot find FETCH_HEAD commit: {e}");
			return false;
		}
	};

	// ── Apply ─────────────────────────────────────────────────────────────────
	if force {
		match repo.reset(fetch_head_commit.as_object(), ResetType::Hard, None) {
			Ok(()) => {
				tracing::info!(dir = %dir.display(), commit = %fetch_head_oid,
							   "git force-reset to FETCH_HEAD");
				true
			}
			Err(e) => {
				tracing::warn!(dir = %dir.display(), "git reset --hard failed: {e}");
				false
			}
		}
	} else {
		let fetch_head_annotated = match repo.find_annotated_commit(fetch_head_oid) {
			Ok(ac) => ac,
			Err(e) => {
				tracing::warn!(dir = %dir.display(),
							   "git: cannot build annotated FETCH_HEAD: {e}");
				return false;
			}
		};

		let (analysis, _) = match repo.merge_analysis(&[&fetch_head_annotated]) {
			Ok(v)  => v,
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
			tracing::warn!(dir = %dir.display(),
						   "git: fast-forward not possible (history diverged); \
							use git_force_pull: true to override");
			return false;
		}

		let refname = match repo.head() {
			Ok(r)  => r.name().unwrap_or("HEAD").to_string(),
			Err(_) => "HEAD".to_string(),
		};

		let result = repo.find_reference(&refname)
			.and_then(|mut r| {
				r.set_target(fetch_head_oid,
							 &format!("fast-forward to {fetch_head_oid}"))?;
				Ok(())
			})
			.and_then(|()| {
				repo.set_head(&refname)?;
				repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
			});

		match result {
			Ok(()) => {
				tracing::info!(dir = %dir.display(), commit = %fetch_head_oid,
							   "git fast-forward to FETCH_HEAD");
				true
			}
			Err(e) => {
				tracing::warn!(dir = %dir.display(), "git fast-forward failed: {e}");
				false
			}
		}
	}
}

// ── Watcher loop ──────────────────────────────────────────────────────────────

async fn run(config: Arc<Config>, gallery_images: GalleryMap) -> Result<()> {
	// Build the SSH verifier once; shared across all git syncs.
	let dns      = Arc::new(DnsResolver::new(&config.network));
	let verifier = Arc::new(SshVerifier::new(dns));

	let (tx, mut rx) = mpsc::unbounded_channel::<notify::Result<Event>>();

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

	let mut last_sync: HashMap<String, Instant> = HashMap::new();

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

		if pending_slugs.is_empty() { continue; }

		let now = Instant::now();

		for slug in pending_slugs.drain() {
			let mut do_git_sync = false;
			let Some(gallery_cfg) = config.galleries.iter().find(|g| g.url == slug) else {
				continue;
			};

			match last_sync.get(&slug) {
				Some(&last) if now.duration_since(last) < SYNC_COOLDOWN => {
					tracing::debug!(gallery = %slug, "git sync skipped: cooldown");
				}
				_ => {
					tracing::debug!(gallery = %slug, "doing git sync");
					do_git_sync = true;
					last_sync.insert(slug.clone(), now); // record sync time now
				}
			}

			// Git sync (fetch + verify + merge/reset) before scanning.
			if let Some(dirs) = git_dirs.get(&slug) {
				for photo_dir in dirs {
					if do_git_sync {
						tracing::info!(dir = photo_dir.dir.to_str(), "git syncing");
						git_sync(photo_dir, &verifier).await;
					}
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
							gallery = %slug, old = old_count,
							new = new_count,
							delta = new_count as i64 - old_count as i64,
							"hot-reloaded gallery"
						);
					} else {
						tracing::trace!(gallery = %slug, count = new_count,
										"poll rescan: no change");
					}
				}
				Err(e) => tracing::error!(gallery = %slug, "rescan failed: {e:#}"),
			}
		}
		tracing::info!("tracing loop end");
		sleep(Duration::from_secs(2));
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
