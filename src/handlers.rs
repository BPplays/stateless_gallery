use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc};
use std::fs::File;
use std::io::Read;

use crate::{config::PhotoDir, template, thumbnail, AppState};

// ─── Query params ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
pub struct SecretQuery {
    #[serde(default)]
    pub secret: String,
}

// ─── Encode / decode helpers ──────────────────────────────────────────────────

pub fn encode_path(path: &std::path::Path) -> String {
    URL_SAFE_NO_PAD.encode(path.to_string_lossy().as_bytes())
}

fn decode_path(encoded: &str) -> Option<PathBuf> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let s = String::from_utf8(bytes).ok()?;
    Some(PathBuf::from(s))
}

// ─── Path guard ───────────────────────────────────────────────────────────────

/// Reject any path not under one of the gallery's photo_dirs.
fn is_allowed(path: &std::path::Path, dirs: &[PhotoDir]) -> bool {
    let Ok(canonical) = path.canonicalize() else { return false };
    dirs.iter().any(|d| {
        d.dir.canonicalize()
            .map(|cd| canonical.starts_with(&cd))
            .unwrap_or(false)
    })
}

// ─── Secret guard ─────────────────────────────────────────────────────────────

fn secret_ok(state: &AppState, slug: &str, supplied: &str) -> bool {
    let Some(gallery) = state.config.galleries.iter().find(|g| g.url == slug) else {
        return false; // unknown gallery
    };
    if !gallery.requires_secret() {
        return true;
    }
    gallery.secret_matches(supplied)
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "text/plain")],
        "401 Unauthorized — wrong or missing ?secret=",
    )
        .into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "404 Not Found").into_response()
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// Serve the favicon.
pub async fn serve_favicon(
    State(state): State<Arc<AppState>>,
) -> Response {
    if let Some(path) = &state.config.global.favicon_png {
        serve_file(path).await
    } else {
        not_found()
    }
}

pub async fn serve_gallery_js () -> Response {
    return include_str!("../static/gallery.js").into_response()
}

/// Serve the gallery index page.
pub async fn gallery_index(
    AxumPath(slug): AxumPath<String>,
    Query(qs): Query<SecretQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    // Validate gallery exists
    let Some(gallery_cfg) = state.config.galleries.iter().find(|g| g.url == slug) else {
        return not_found();
    };

    // Check secret
    if gallery_cfg.requires_secret() && !gallery_cfg.secret_matches(&qs.secret) {
        return unauthorized();
    }

    // Read current image list (cheap RwLock read)
    let images = {
        let map = state.gallery_images.read().await;
        map.get(&slug).cloned().unwrap_or_default()
    };

    Html(template::render(gallery_cfg, &images, &qs.secret)).into_response()
}

/// Serve a thumbnail (generated on demand, cached on disk).
pub async fn serve_thumbnail(
    AxumPath((slug, encoded)): AxumPath<(String, String)>,
    Query(qs): Query<SecretQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let Some(gallery_cfg) = state.config.galleries.iter().find(|g| g.url == slug) else {
        return not_found();
    };
    if gallery_cfg.requires_secret() && !gallery_cfg.secret_matches(&qs.secret) {
        return unauthorized();
    }

    let Some(path) = decode_path(&encoded) else {
        return (StatusCode::BAD_REQUEST, "invalid path encoding").into_response();
    };
    if !is_allowed(&path, &gallery_cfg.photo_dirs) {
        return (StatusCode::FORBIDDEN, "path outside allowed directories").into_response();
    }

    let cache_dir = state.config.cache_dir.clone();
    let cfg = state.config.thumbnails.clone();
    let path_clone = path.clone();

    let thumb_result =
        tokio::task::spawn_blocking(move || thumbnail::get_or_create_thumbnail(&path_clone, &cache_dir, &cfg))
            .await;

    let serve_path = match thumb_result {
        Ok(Ok(Some(p))) => p,
        Ok(Ok(None)) => path,
        Ok(Err(e)) => {
            tracing::error!("thumbnail generation failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "thumbnail generation failed").into_response();
        }
        Err(e) => {
            tracing::error!("spawn_blocking panicked: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    serve_file(&serve_path).await
}

/// Serve the original full-size image.
pub async fn serve_full(
    AxumPath((slug, encoded)): AxumPath<(String, String)>,
    Query(qs): Query<SecretQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let Some(gallery_cfg) = state.config.galleries.iter().find(|g| g.url == slug) else {
        return not_found();
    };
    if gallery_cfg.requires_secret() && !gallery_cfg.secret_matches(&qs.secret) {
        return unauthorized();
    }

    let Some(path) = decode_path(&encoded) else {
        return (StatusCode::BAD_REQUEST, "invalid path encoding").into_response();
    };
    if !is_allowed(&path, &gallery_cfg.photo_dirs) {
        return (StatusCode::FORBIDDEN, "path outside allowed directories").into_response();
    }

    serve_file(&path).await
}

/// Serve static files
pub async fn serve_static(
    State(_state): State<Arc<AppState>>,
) -> Response {
    // Only serve gallery.js from static directory
    let static_path = std::path::Path::new("static").join("gallery.js");

    // Serve the file if it exists, otherwise return not found
    serve_file(&static_path).await
}

/// Serve octicon SVGs
pub async fn serve_octicon(
    AxumPath(icon_name): AxumPath<String>,
    State(_state): State<Arc<AppState>>,
) -> Response {
    // Use include_dir to statically include all the octicons
    const OCTICONS: include_dir::Dir = include_dir::include_dir!("icons/octicons/icons");

    // Try to find and serve the requested icon
    let icon_path = format!("{}.svg", icon_name);

    if let Some(icon_file) = OCTICONS.get_file(&icon_path) {
        let Some(data) = icon_file.contents_utf8() else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid icon encoding",
            )
                .into_response();
        };

        (
            [
                (header::CONTENT_TYPE, "image/svg+xml".to_string()),
                (header::CACHE_CONTROL, "public, max-age=86400".to_string()),
            ],
            data,
        )
            .into_response()
    } else {
        (StatusCode::NOT_FOUND, "icon not found").into_response()
    }
}

// ─── File serving ─────────────────────────────────────────────────────────────

async fn serve_file(path: &std::path::Path) -> Response {
    match tokio::fs::read(path).await {
        Ok(data) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            (
                [
                    (header::CONTENT_TYPE, mime),
                    (header::CACHE_CONTROL, "public, max-age=86400".to_string()),
                ],
                data,
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!("could not read {}: {e}", path.display());
            (StatusCode::NOT_FOUND, "file not found").into_response()
        }
    }
}
