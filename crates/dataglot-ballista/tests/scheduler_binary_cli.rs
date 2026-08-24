//! `dataglot-ballista-scheduler` binary subprocess tests — the
//! scheduler counterpart to `executor_binary_cli.rs` ( #1).
//!
//! Exercises CLI surface only: `--help` / `--version`, and the two
//! fail-fast paths that fire *before* any bind or network — the §12
//! default-deny plaintext refusal and the HA-timing validation. It
//! does NOT stand up a cluster; the boot + register + query roundtrip
//! is covered by `multi_process_cluster.rs` / `scheduler_death.rs`.
//!
//! These run as part of the standard `cargo test -p dataglot-ballista`
//! invocation (not Docker-gated). They use
//! `assert_cmd::Command::cargo_bin("dataglot-ballista-scheduler")` to
//! locate the binary in `target/{debug,release}/`.

use assert_cmd::Command;
use predicates::prelude::*;

/// `--help` exits 0 and prints recognisable text. Smoke test that the
/// binary builds and clap surfaces our flags (the `long_about` block
/// plus a few stable flag names).
#[test]
fn help_flag_prints_usage_and_exits_zero() {
    let mut cmd = Command::cargo_bin("dataglot-ballista-scheduler").expect("binary built");
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Boots a Ballista scheduler"))
        .stdout(predicate::str::contains("--bind-port"))
        .stdout(predicate::str::contains("--external-host"))
        .stdout(predicate::str::contains("--namespace"));
}

/// `--version` exits 0 (clap auto-derives). Catches the regression
/// shape where `#[command(...)]` defaults are accidentally dropped in
/// a future refactor of `SchedulerArgs`.
#[test]
fn version_flag_exits_zero() {
    let mut cmd = Command::cargo_bin("dataglot-ballista-scheduler").expect("binary built");
    cmd.arg("--version");
    cmd.assert().success();
}

/// §12 default-deny — booting with neither a TLS bundle nor
/// `--insecure` must refuse *before* binding, not silently come up in
/// plaintext. Pins the security posture at the binary level. Bind port
/// 0 keeps the test off any real port even if the refusal regressed.
#[test]
fn plaintext_without_insecure_is_refused_before_binding() {
    let mut cmd = Command::cargo_bin("dataglot-ballista-scheduler").expect("binary built");
    cmd.args(["--bind-port", "0"]);
    cmd.timeout(std::time::Duration::from_secs(10));
    cmd.assert().failure().stderr(predicate::str::contains(
        "refusing to boot in plaintext mode",
    ));
}

/// HA-timing validation — a heartbeat interval not strictly less than
/// the lease duration would let the lease expire before the next
/// refresh, so the scheduler must reject it up front. `--insecure`
/// clears the default-deny gate so validation is what's under test;
/// `--ha-state-uri` selects the HA path where the check runs. The
/// unroutable-looking file URI is never dereferenced — validation
/// fails first.
#[test]
fn ha_heartbeat_not_less_than_lease_is_rejected() {
    let mut cmd = Command::cargo_bin("dataglot-ballista-scheduler").expect("binary built");
    cmd.args([
        "--insecure",
        "--ha-state-uri",
        "file:///tmp/dataglot-oss138-never-read",
        "--ha-lease-duration-secs",
        "5",
        "--ha-heartbeat-interval-secs",
        "10",
    ]);
    cmd.timeout(std::time::Duration::from_secs(10));
    cmd.assert().failure().stderr(
        predicate::str::contains("ha-heartbeat-interval-secs")
            .and(predicate::str::contains("strictly less than")),
    );
}
