//! Embedded operational-dashboard SPA — the React UI
//! in `frontend/dist/`, baked into `dataglot-server` via `rust-embed`
//! and served at `/ui`.
//!
//! Gated behind the `dashboard` cargo feature: default builds carry no
//! UI bytes and skip the Node build in `build.rs`, keeping the core
//! crate fast and JVM/Node-free. The Vite app builds with `base: "/ui/"`
//! so asset URLs arrive as `/ui/assets/…`; the `serve` handler strips
//! the `/ui` mount prefix before the embed lookup and falls back to
//! `index.html` for client-side routing.

use axum::{
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

/// The built dashboard SPA. `build.rs` guarantees `frontend/dist/`
/// exists (real `vite build`, or a stub when Node is absent) whenever
/// this module is compiled, so the embed is never empty.
#[derive(RustEmbed)]
#[folder = "frontend/dist"]
struct Assets;

/// Axum handler for the `/ui` and `/ui/{*path}` routes. Asset paths
/// resolve directly; any unknown path returns `index.html` so the
/// client-side tab state survives deep links / refresh.
pub async fn serve(uri: Uri) -> Response {
    // Routes are only `/ui` and `/ui/...`, so the path always starts
    // with `/ui`; strip that mount prefix, then the leading slash.
    let raw = uri
        .path()
        .strip_prefix("/ui")
        .unwrap_or(uri.path())
        .trim_start_matches('/');
    let path = if raw.is_empty() { "index.html" } else { raw };

    if let Some(asset) = Assets::get(path) {
        return asset_response(&asset, cache_control_for(path));
    }
    match Assets::get("index.html") {
        Some(index) => asset_response(&index, cache_control_for("index.html")),
        None => (StatusCode::NOT_FOUND, "dashboard UI not built").into_response(),
    }
}

/// Long-lived, immutable cache for content-hashed assets.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// Force revalidation for the app shell and any non-hashed file.
const NO_CACHE: &str = "no-cache";

/// Cache-Control by path. Vite emits **content-hashed** filenames under
/// `assets/` (safe to cache forever); everything else — above all
/// `index.html`, which references those hashes — must revalidate so a
/// rebuilt UI isn't hidden behind a stale shell.
fn cache_control_for(path: &str) -> &'static str {
    if path.starts_with("assets/") {
        IMMUTABLE
    } else {
        NO_CACHE
    }
}

fn asset_response(asset: &rust_embed::EmbeddedFile, cache_control: &'static str) -> Response {
    let mime = asset.metadata.mimetype();
    (
        [
            (header::CONTENT_TYPE, mime.to_string()),
            (header::CACHE_CONTROL, cache_control.to_string()),
        ],
        asset.data.clone().into_owned(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_html_is_embedded() {
        assert!(
            Assets::get("index.html").is_some(),
            "frontend/dist/index.html must be embedded (build.rs stub or real vite build)"
        );
    }

    #[test]
    fn cache_policy_never_caches_shell_but_immutably_caches_hashed_assets() {
        assert_eq!(cache_control_for("index.html"), NO_CACHE);
        assert_eq!(cache_control_for("favicon.ico"), NO_CACHE);
        assert_eq!(cache_control_for("assets/index-CpiWUkU2.js"), IMMUTABLE);
        assert_eq!(cache_control_for("assets/index-DiZwhKSr.css"), IMMUTABLE);
    }
}
