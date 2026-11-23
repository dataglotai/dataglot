//! Shared test-only helpers for the Dataglot workspace.
//!
//! Dev tooling (`publish = false`): pulled in as a `[dev-dependencies]`
//! entry by the crates whose tests need it. Depends on nothing but `std`
//! so it stays a leaf and never risks a dependency cycle.

pub mod s3;

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::{Mutex, OnceLock};

/// Process-wide set of ports already handed out by [`reserve_loopback_port`].
/// `OnceLock` (not a `const` initializer) because `HashSet::new()` isn't
/// `const` on stable — keeps the crate MSRV-friendly.
fn handed_out() -> &'static Mutex<HashSet<u16>> {
    static PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    PORTS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Reserve a loopback TCP port for a test server to bind.
///
/// Race-hardened replacement for the ~18 copy-pasted
/// `bind(":0"); read port; drop; return port` helpers. Those all shared a
/// TOCTOU window between dropping the probe listener and the server
/// re-binding — but the dominant CI flake was **intra-process**: two tests
/// running concurrently in the same test binary received the *same*
/// ephemeral port from the OS (each probe binds `:0`, reads the port, then
/// frees it, so the allocator can hand the same number to the next probe),
/// and the second server then failed to bind with
/// `Address already in use`.
///
/// This helper records every port it returns in a process-wide set and
/// only returns one not already handed to a concurrent caller in this
/// process, eliminating that intra-process collision. The cross-*process*
/// window (separate test binaries) is unchanged, but it is far rarer than
/// the in-binary collision this removes.
///
/// # Panics
/// Panics if an ephemeral port cannot be bound, or if 1000 consecutive
/// probes all collided with already-handed-out ports (never observed in
/// practice — it would mean the process reserved ~1000 live ports).
#[must_use]
pub fn reserve_loopback_port() -> u16 {
    for _ in 0..1000 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral loopback port");
        let port = listener
            .local_addr()
            .expect("resolve the bound local address")
            .port();
        // Free the probe listener so the caller's server can bind the port.
        drop(listener);
        if handed_out()
            .lock()
            .expect("port registry mutex is not poisoned")
            .insert(port)
        {
            return port;
        }
        // Port was already handed to another caller this process — retry.
    }
    panic!("could not reserve a unique loopback port after 1000 attempts");
}

/// Whether `image` is **confirmed** unpullable, so a container test should
/// skip rather than fail.
///
/// MinIO withdrew its Docker Hub images and has since closed `quay.io` to
/// unauthenticated pulls, leaving no public image to pin. A pull failure for
/// that reason says nothing about our code, and failing on it turns every PR
/// red on a required check.
///
/// # Only a registry refusal skips
///
/// The classification is deliberately strict, because a skip that is too
/// eager is worse than the failure it replaces — it removes coverage from a
/// run that still reports green.
///
/// * The *registry* answers and refuses us → **skip**. Permanent; no retry
///   helps.
/// * Anything else — a timeout, no `docker`, a local daemon or permission
///   problem, a transient 5xx → **do not skip**. The caller proceeds, the
///   real container start produces the real error, and the integration
///   workflow's `retry-on-container-flake.sh` wrapper gets to do its job.
///
/// Local daemon faults are excluded explicitly. `permission denied while
/// trying to connect to the Docker daemon socket` contains "denied", so a
/// naive substring match reads a broken local setup as a registry refusal
/// and silently skips the whole suite.
///
/// # Blocking
///
/// Synchronous: this crate is a dependency-free leaf and will not take an
/// async runtime for one probe. Callers in async tests must wrap it in
/// `tokio::task::spawn_blocking` — it can block for the full timeout.
///
/// Results are cached per image for the life of the process, so a suite with
/// a dozen gated tests probes each registry once rather than once per test.
#[must_use]
pub fn image_unavailable(image: &str) -> bool {
    use std::sync::Arc;

    type Slot = Arc<Mutex<Option<bool>>>;
    static CACHE: OnceLock<Mutex<std::collections::HashMap<String, Slot>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));

    // Two locks on purpose. The map lock is held only long enough to hand
    // out this image's slot, so it never covers the probe. The slot lock is
    // then held *across* the probe, so concurrent tests asking about the
    // same image wait for one answer instead of each spending up to the full
    // timeout on their own `docker` call. Different images still proceed in
    // parallel.
    let slot: Slot = {
        let mut map = cache.lock().expect("probe cache mutex is not poisoned");
        Arc::clone(
            map.entry(image.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(None))),
        )
    };

    let mut slot = slot.lock().expect("probe slot mutex is not poisoned");
    if let Some(known) = *slot {
        return known;
    }
    let verdict = probe(image);
    *slot = Some(verdict);
    verdict
}

/// Is this exact reference already in the local Docker image cache?
///
/// Checked before the registry, because `docker manifest inspect` always
/// asks the registry. A developer or self-hosted runner that already pulled
/// the image can still run the test after losing registry access, and
/// skipping there would turn runnable coverage into a green no-op.
fn present_locally(image: &str) -> bool {
    // Bounded like the registry call below: an unresponsive daemon makes
    // `docker image inspect` hang just as readily as `manifest inspect`, and
    // this one runs *first*, so an unbounded wait here would stall every
    // gated test before the registry timeout could ever apply.
    matches!(run_bounded(&["image", "inspect", image]), Some((true, _)))
}

/// Run `docker <args>` with a deadline, returning `(succeeded, stderr)`.
///
/// `None` means the command could not be started or never answered — never
/// confuse that with a verdict from Docker.
///
/// The child stays in this thread so it can still be killed on timeout; only
/// the stderr pipe moves. Reading that pipe to EOF is *usually* the wait,
/// because it closes when the process exits — but not always: a wrapper that
/// redirects or closes stderr and then blocks reaches EOF while still
/// running. So process exit is checked against the same deadline too
/// ([`reap_by`]), and on expiry the child is killed and reaped.
fn run_bounded(args: &[&str]) -> Option<(bool, String)> {
    run_bounded_program("docker", args, std::time::Duration::from_secs(20))
}

/// [`run_bounded`] with the program and deadline as parameters, so the
/// deadline handling can be tested without Docker.
fn run_bounded_program(
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> Option<(bool, String)> {
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Instant;

    let deadline = Instant::now() + timeout;
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let pipe = child.stderr.take();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_string(&mut buf);
        }
        let _ = tx.send(buf);
    });

    let Ok(stderr) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let status = reap_by(&mut child, deadline)?;
    Some((status.success(), stderr))
}

/// Wait for `child` to exit, but no later than `deadline`; past it, kill and
/// reap the child and return `None`.
///
/// `Child::wait` has no timeout, so this polls `try_wait`. The pause between
/// polls is a `recv_timeout` on a channel that never receives — a bounded
/// wait without `thread::sleep`, which is disallowed workspace-wide (this
/// leaf crate has no async runtime to sleep on instead).
fn reap_by(
    child: &mut std::process::Child,
    deadline: std::time::Instant,
) -> Option<std::process::ExitStatus> {
    use std::time::{Duration, Instant};

    let (_never_sends, pause) = std::sync::mpsc::channel::<()>();
    loop {
        let exited = match child.try_wait() {
            Ok(exited) => exited,
            // Can't tell whether it exited: treat like a timeout and clean
            // up, rather than leaving a child (and its stderr reader) behind.
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        };
        if let Some(status) = exited {
            return Some(status);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        let _ = pause.recv_timeout(left.min(Duration::from_millis(25)));
    }
}

/// What `docker manifest inspect`'s failure actually means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// The registry refused to serve us — skip the gated test.
    RegistryRefused,
    /// Something on this machine is broken. Not a registry verdict; run the
    /// test so the real failure surfaces instead of hiding behind a skip.
    LocalFault,
    /// Failure we do not recognise. Treated like `LocalFault`: never skip on
    /// a message we have not actually seen a registry produce.
    Unrecognised,
}

/// Classify a failed `docker manifest inspect` from its stderr alone.
///
/// Split out from the probe so it can be tested without a Docker daemon.
/// Every previous bug here was a *misclassification* — a local fault read as
/// a registry refusal, silently turning real coverage into a green no-op —
/// and none of them were reachable by a test while this logic lived inline
/// behind a live `docker` call. The table below is the regression suite.
fn classify(stderr: &str) -> Verdict {
    let stderr = stderr.to_ascii_lowercase();

    // Checked FIRST, because several local faults contain a refusal
    // substring and would otherwise be read as a registry verdict:
    //   "permission denied while trying to connect ..."  contains "denied"
    //   "executable file not found in $path"             contains "not found"
    // Both of those shipped as bugs. Order is the fix, so keep this first.
    const LOCAL_FAULTS: [&str; 9] = [
        // Daemon unreachable or not running.
        "permission denied while trying to connect",
        "cannot connect to the docker daemon",
        "is the docker daemon running",
        "dial unix",
        // Credential helper missing or broken — e.g. a Docker Desktop
        // config.json copied onto a Linux runner that has no
        // `docker-credential-desktop` on PATH.
        "executable file not found",
        "error getting credentials",
        "docker-credential-",
        "exec format error",
        // Config present but unreadable/corrupt.
        "error loading config file",
    ];
    if LOCAL_FAULTS.iter().any(|f| stderr.contains(f)) {
        return Verdict::LocalFault;
    }

    // What the registry says when it will not serve us.
    //
    // Every string here was captured from a real `docker manifest inspect`
    // against a real registry, not guessed, and each is specific enough that
    // ordinary OS or tooling errors cannot contain it. The captures:
    //
    //   Docker Hub, repository withdrawn  -> "denied: requested access to the
    //                                         resource is denied" +
    //                                        "unauthorized: authentication required"
    //   Docker Hub, repository nonexistent-> same pair (indistinguishable by design)
    //   quay.io, unauthenticated          -> "no such manifest: <ref>"
    //   Docker Hub, tag missing           -> "no such manifest: <ref>"
    //   ghcr.io, tag missing              -> "manifest unknown"
    //
    // Note what is NOT here: a bare "not found". No registry emits it, so it
    // only ever matched things like "executable file not found in $PATH" and
    // "command not found" — local faults wearing a refusal's clothes. The
    // same reasoning retired a bare "denied", which "permission denied"
    // matched. Specific strings are the real defence; LOCAL_FAULTS above is
    // the backstop, not the other way round.
    const REFUSALS: [&str; 4] = [
        "no such manifest",
        "manifest unknown",
        "unauthorized: authentication required",
        "requested access to the resource is denied",
    ];
    if REFUSALS.iter().any(|r| stderr.contains(r)) {
        return Verdict::RegistryRefused;
    }

    Verdict::Unrecognised
}

/// One uncached availability check, with a deadline on the registry call.
fn probe(image: &str) -> bool {
    if present_locally(image) {
        return false;
    }

    let Some((ok, stderr)) = run_bounded(&["manifest", "inspect", image]) else {
        // No usable `docker`, or it never answered. Inconclusive — let the
        // caller fail for real.
        eprintln!("`{image}` probe did not complete; proceeding so the real failure surfaces");
        return false;
    };
    if ok {
        return false;
    }

    match classify(&stderr) {
        Verdict::RegistryRefused => {
            eprintln!(
                "SKIP: `{image}` is unpullable — the registry refused us and it is not in \
                 the local image cache. Coverage that needs this image is NOT exercised by \
                 this run."
            );
            true
        }
        Verdict::LocalFault => {
            eprintln!(
                "`{image}` probe hit a local Docker fault, not a registry refusal: {}",
                stderr.trim()
            );
            false
        }
        Verdict::Unrecognised => {
            eprintln!(
                "`{image}` probe failed but the registry did not refuse us; proceeding so \
                 the real failure surfaces: {}",
                stderr.trim()
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `true` when a POSIX `sh` can be started, which the deadline tests
    /// below use as a stand-in for a misbehaving `docker`.
    fn have_sh() -> bool {
        std::process::Command::new("sh")
            .args(["-c", "true"])
            .status()
            .is_ok_and(|s| s.success())
    }

    /// A child that closes stderr and keeps running reaches EOF on the pipe
    /// long before it exits. The deadline must still bound the call: it
    /// returns `None` (no answer) close to the timeout instead of blocking in
    /// `wait()` until the child finishes on its own.
    #[test]
    fn a_child_that_closes_stderr_early_is_still_bounded_by_the_deadline() {
        if !have_sh() {
            return;
        }
        let start = std::time::Instant::now();
        let got = run_bounded_program(
            "sh",
            &["-c", "exec 2>&-; sleep 30"],
            std::time::Duration::from_secs(1),
        );
        let elapsed = start.elapsed();
        assert_eq!(got, None, "an unanswered call is not a verdict");
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "the deadline must bound process exit too, took {elapsed:?}"
        );
    }

    /// The ordinary path still reports the exit status and stderr.
    #[test]
    fn a_child_that_exits_reports_its_status_and_stderr() {
        if !have_sh() {
            return;
        }
        let got = run_bounded_program(
            "sh",
            &["-c", "echo refused >&2; exit 3"],
            std::time::Duration::from_secs(20),
        );
        let (ok, stderr) = got.expect("the child answered");
        assert!(!ok);
        assert_eq!(stderr.trim(), "refused");
    }

    /// Every reserved port is unique within the process — the core
    /// guarantee that removes the intra-binary collision flake.
    #[test]
    fn reserved_ports_are_unique_within_the_process() {
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let port = reserve_loopback_port();
            assert_ne!(port, 0, "reserved port must be non-zero");
            assert!(seen.insert(port), "port {port} was handed out twice");
        }
    }

    /// Local Docker faults must never read as registry refusals. Each
    /// string here is a real `docker manifest inspect` stderr; the first
    /// two are regressions — both shipped classed as refusals, which
    /// silently skipped tests that should have run and hidden the broken
    /// machine instead of reporting it.
    #[test]
    fn local_docker_faults_are_not_registry_refusals() {
        for stderr in [
            // contains "denied"
            "Got permission denied while trying to connect to the Docker daemon socket",
            // contains "not found"
            "error getting credentials - err: exec: \"docker-credential-desktop\": \
             executable file not found in $PATH",
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. \
             Is the docker daemon running?",
            "error during connect: Get \"http://%2Fvar%2Frun%2Fdocker.sock/_ping\": \
             dial unix /var/run/docker.sock: connect: connection refused",
            "docker-credential-osxkeychain: exec format error",
            "error loading config file: /root/.docker/config.json: unexpected end of JSON input",
        ] {
            assert_eq!(
                classify(stderr),
                Verdict::LocalFault,
                "local fault misclassified, tests would silently skip: {stderr}"
            );
        }
    }

    /// The messages real registries return when they will not serve an
    /// unauthenticated client. These are the only strings that may skip.
    #[test]
    fn registry_refusals_are_recognised() {
        for stderr in [
            // quay.io, unauthenticated — arrives shaped like a not-found
            "no such manifest: quay.io/minio/minio:latest",
            "errors:\ndenied: requested access to the resource is denied\n\
             unauthorized: authentication required",
            "unauthorized: authentication required",
            "manifest unknown",
        ] {
            assert_eq!(
                classify(stderr),
                Verdict::RegistryRefused,
                "registry refusal not recognised, test would fail instead of skip: {stderr}"
            );
        }
    }

    /// The property that actually matters, stated once over both tables:
    /// a test is skipped only for a verified registry refusal. Local faults
    /// and unrecognised failures both run the test, so a broken machine
    /// reports itself instead of going quietly green.
    #[test]
    fn only_registry_refusals_cause_a_skip() {
        let skips = |s: &str| classify(s) == Verdict::RegistryRefused;
        assert!(skips("no such manifest: quay.io/minio/minio:latest"));
        for not_a_refusal in [
            "Got permission denied while trying to connect to the Docker daemon socket",
            "error getting credentials - err: exec: \"docker-credential-desktop\": \
             executable file not found in $PATH",
            "creds-helper-foo: command not found",
            "no space left on device",
            "",
        ] {
            assert!(
                !skips(not_a_refusal),
                "this would silently skip a runnable test: {not_a_refusal}"
            );
        }
    }

    /// Anything we have not actually seen a registry produce must not skip.
    #[test]
    fn unknown_failures_do_not_skip() {
        for stderr in [
            "",
            "context deadline exceeded",
            "i/o timeout",
            // A credential helper we have no pattern for. It matches no
            // LOCAL_FAULTS entry, so it lands here — and must still not
            // skip. A blocklist of local faults can never be exhaustive,
            // which is exactly why REFUSALS carries no generic substring:
            // the allowlist has to be the exact thing registries say.
            "creds-helper-foo: command not found",
        ] {
            assert_eq!(classify(stderr), Verdict::Unrecognised, "{stderr}");
        }
    }

    /// A reserved port is actually bindable right after it's returned
    /// (the probe listener was dropped, so the caller can claim it).
    #[test]
    fn reserved_port_is_bindable() {
        let port = reserve_loopback_port();
        let _listener = TcpListener::bind(("127.0.0.1", port))
            .expect("a freshly reserved port must be bindable");
    }
}
