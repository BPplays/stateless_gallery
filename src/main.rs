mod config;
mod gallery;
mod handlers;
mod template;
mod thumbnail;
mod watcher;

use anyhow::{Context, Result, bail};
use axum::{routing::get, Router};
use clap::Parser;
use config::Config;
use gallery::ImageEntry;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "photo-gallery",
    about = "Stateless multi-gallery photo server — backed by a YAML config and a thumbnail cache"
)]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(short = 'c', long = "config", default_value = "gallery.yaml")]
    config: PathBuf,
}

// ─── Shared application state ─────────────────────────────────────────────────

pub struct AppState {
    /// Static configuration (never mutated after startup).
    pub config: Arc<Config>,
    /// Live image lists, keyed by gallery URL slug.
    /// Updated by the filesystem watcher without restarting.
    pub gallery_images: Arc<RwLock<HashMap<String, Vec<ImageEntry>>>>,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // ── Load & validate config ────────────────────────────────────────────────
    let config_text = std::fs::read_to_string(&cli.config)
        .with_context(|| format!("could not read config file: {}", cli.config.display()))?;
    let config: Config =
        yaml_serde::from_str(&config_text).context("failed to parse config YAML")?;

    if config.galleries.is_empty() {
        bail!("config must define at least one gallery under `galleries:`");
    }

    // Check for duplicate slugs
    let mut seen_slugs = std::collections::HashSet::new();
    for g in &config.galleries {
        if g.url.is_empty() {
            bail!("gallery {:?} has an empty `url` field", g.name);
        }
        if !seen_slugs.insert(g.url.clone()) {
            bail!("duplicate gallery url slug {:?}", g.url);
        }
    }

    tracing::info!(
        config = %cli.config.display(),
        galleries = config.galleries.len(),
        "loaded configuration"
    );

    // ── Initial directory scan ────────────────────────────────────────────────
    let mut gallery_map: HashMap<String, Vec<ImageEntry>> = HashMap::new();
    for gallery_cfg in &config.galleries {
        let images = gallery::scan_gallery(gallery_cfg)?;
        if images.is_empty() {
            tracing::warn!(
                gallery = %gallery_cfg.url,
                "no images found — check photo_dirs"
            );
        }
        gallery_map.insert(gallery_cfg.url.clone(), images);
    }

    let gallery_images: Arc<RwLock<HashMap<String, Vec<ImageEntry>>>> =
        Arc::new(RwLock::new(gallery_map));

    // ── Ensure cache directory exists ─────────────────────────────────────────
    if config.thumbnails.enabled {
        std::fs::create_dir_all(&config.cache_dir).with_context(|| {
            format!("could not create cache_dir: {}", config.cache_dir.display())
        })?;
        tracing::info!(cache_dir = %config.cache_dir.display(), "thumbnail cache ready");
    }

    let config = Arc::new(config);

    // ── Start filesystem watcher ──────────────────────────────────────────────
    watcher::spawn(Arc::clone(&config), Arc::clone(&gallery_images));

    // ── Build router ──────────────────────────────────────────────────────────
    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        gallery_images,
    });

    let app = Router::new()
        // Gallery index:  GET /{slug}?secret=...
        .route("/{slug}", get(handlers::gallery_index))
        // Thumbnail:      GET /{slug}/thumb/{encoded}?secret=...
        .route("/{slug}/thumb/{encoded}", get(handlers::serve_thumbnail))
        // Full-size:      GET /{slug}/full/{encoded}?secret=...
        .route("/{slug}/full/{encoded}", get(handlers::serve_full))
        .with_state(state);

    // ── Log all gallery URLs at startup ───────────────────────────────────────
    let addr: std::net::SocketAddr = config.bind.parse().with_context(|| {
        format!("invalid bind address: {}", config.bind)
    })?;

    tracing::info!(address = %addr, "server starting");
    for g in &config.galleries {
        if g.requires_secret() {
            tracing::info!(
                "  {} → http://{}/{}?secret={}",
                g.name, addr, g.url, g.secret
            );
        } else {
            tracing::info!("  {} → http://{}/{}", g.name, addr, g.url);
        }
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
