//! Build script for `dataglot-server`.
//!
//! Its only job is the embedded operational dashboard,
//! and only when the `dashboard` cargo feature is enabled — default
//! builds do nothing here, so the core crate's build stays fast and
//! Node-free.
//!
//! With `--features dashboard` it produces `frontend/dist/` — the built
//! React SPA that `rust-embed` (see `src/embed.rs`) bakes into the
//! binary and serves at `/ui`. Behaviour mirrors the testbench:
//!
//!   * `DATAGLOT_SKIP_FRONTEND_BUILD=1` → skip the vite build, just
//!     guarantee `frontend/dist/index.html` exists (a stub). Lets a
//!     `--features dashboard` build compile without Node.
//!   * Node/npm absent → same stub path, with a warning.
//!   * Otherwise → `npm ci` (only if `node_modules` is missing) then
//!     `npm run build`. On failure, warn + stub rather than failing the
//!     crate build.

use std::path::Path;
use std::process::Command;

fn main() {
    // Only the `dashboard` feature embeds a UI; otherwise this is a no-op.
    if std::env::var_os("CARGO_FEATURE_DASHBOARD").is_none() {
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let frontend = Path::new(manifest).join("frontend");
    let dist = frontend.join("dist");

    for rel in [
        "frontend/src",
        "frontend/index.html",
        "frontend/package.json",
        "frontend/package-lock.json",
        "frontend/vite.config.ts",
        "frontend/tsconfig.json",
    ] {
        println!("cargo:rerun-if-changed={manifest}/{rel}");
    }
    println!("cargo:rerun-if-env-changed=DATAGLOT_SKIP_FRONTEND_BUILD");

    let skip =
        std::env::var("DATAGLOT_SKIP_FRONTEND_BUILD").is_ok_and(|v| v != "0" && !v.is_empty());
    if skip {
        warn("DATAGLOT_SKIP_FRONTEND_BUILD set — skipping vite build, using stub dist");
        ensure_stub(&dist);
        return;
    }

    if !command_exists("npm") {
        warn("npm not found on PATH — skipping vite build, using stub dist (install Node to build the dashboard)");
        ensure_stub(&dist);
        return;
    }

    if !frontend.join("node_modules").is_dir()
        && !run(Command::new("npm").arg("ci").current_dir(&frontend))
    {
        warn("`npm ci` failed — using stub dist");
        ensure_stub(&dist);
        return;
    }

    if !run(Command::new("npm")
        .args(["run", "build"])
        .current_dir(&frontend))
    {
        warn("`npm run build` failed — using stub dist");
        ensure_stub(&dist);
        return;
    }

    ensure_stub(&dist); // no-op if index.html already exists
}

fn run(cmd: &mut Command) -> bool {
    match cmd.status() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            warn(&format!("command exited with {s}"));
            false
        }
        Err(e) => {
            warn(&format!("failed to spawn command: {e}"));
            false
        }
    }
}

fn command_exists(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .status()
        .is_ok_and(|s| s.success())
}

/// Guarantee `dist/index.html` exists so `rust-embed`'s `#[folder]`
/// never points at a missing directory. No-op when a real build wrote it.
fn ensure_stub(dist: &Path) {
    if dist.join("index.html").is_file() {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(dist) {
        warn(&format!("could not create {}: {e}", dist.display()));
        return;
    }
    let stub = "<!doctype html><html><head><meta charset=\"utf-8\">\
<title>Dataglot dashboard</title></head><body style=\"font-family:system-ui;\
background:#0e1116;color:#e7ecf3;padding:2rem\">\
<h1>Dataglot dashboard not built</h1>\
<p>This binary was compiled with <code>--features dashboard</code> but without \
the frontend bundle (DATAGLOT_SKIP_FRONTEND_BUILD set, or Node absent at build \
time). Rebuild with Node available, or run the dev server: \
<code>cd crates/dataglot-server/frontend &amp;&amp; npm run dev</code>.</p>\
</body></html>";
    if let Err(e) = std::fs::write(dist.join("index.html"), stub) {
        warn(&format!("could not write stub index.html: {e}"));
    }
}

fn warn(msg: &str) {
    println!("cargo:warning=dataglot-server/build.rs: {msg}");
}
