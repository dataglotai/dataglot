//! `dataglot-ballista-executor` binary subprocess tests — Phase 2
//! slice 5a.
//!
//! Exercises CLI surface only: --help, fail-fast on bad
//! --credentials-config. Does NOT stand up a scheduler — multi-process
//! roundtrip tests (boot scheduler, spawn binary, run a SELECT) are
//! a follow-up sub-slice; their cost (testcontainer scheduler boot +
//! subprocess race-condition management) is heavier than slice 5a's
//! claim.
//!
//! These tests run as part of the standard `cargo test
//! -p dataglot-ballista` invocation (not Docker-gated). They use
//! `assert_cmd::Command::cargo_bin("dataglot-ballista-executor")` to
//! locate the binary in `target/{debug,release}/`.

use assert_cmd::Command;
use predicates::prelude::*;

/// `--help` exits 0 and prints recognisable text. Smoke test that
/// the binary builds and clap surfaces our flags.
#[test]
fn help_flag_prints_usage_and_exits_zero() {
    let mut cmd = Command::cargo_bin("dataglot-ballista-executor").expect("binary built");
    cmd.arg("--help");
    cmd.assert()
        .success()
        // `--help` shows `long_about` text in clap-derive's default
        // layout; check for a stable phrase from that block.
        .stdout(predicate::str::contains("Boots a Ballista executor"))
        .stdout(predicate::str::contains("--credentials-config"))
        .stdout(predicate::str::contains("--scheduler-host"))
        .stdout(predicate::str::contains("--bind-port"));
}

/// Slice 3b fail-fast — passing `--credentials-config` pointing at a
/// non-existent file exits non-zero before any scheduler RPC.
/// `--scheduler-host` is deliberately set to an unroutable address so
/// even if the fail-fast logic regressed, the test wouldn't hang on
/// a network call — it would error eventually with a different
/// message. The assertion specifically looks for the
/// credentials-config message, which only fires on the
/// pre-RPC path.
#[test]
fn missing_credentials_config_exits_non_zero_before_rpc() {
    let mut cmd = Command::cargo_bin("dataglot-ballista-executor").expect("binary built");
    cmd.args([
        "--credentials-config",
        "/tmp/dataglot-slice-5a-never-exists.json",
        "--scheduler-host",
        "192.0.2.1", // RFC 5737 reserved — guaranteed unroutable
        "--scheduler-port",
        "1",
    ]);
    cmd.timeout(std::time::Duration::from_secs(10));
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("credentials-config load failed"));
}

/// Slice 3b fail-fast — malformed JSON in the credentials config
/// also exits non-zero. Distinct stderr line from the missing-file
/// case so an operator can tell apart "wrong path" vs "bad file".
#[test]
fn malformed_credentials_config_exits_non_zero_before_rpc() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), b"{ this is not JSON").expect("write tmp");

    let mut cmd = Command::cargo_bin("dataglot-ballista-executor").expect("binary built");
    cmd.args([
        "--credentials-config",
        tmp.path().to_str().unwrap(),
        "--scheduler-host",
        "192.0.2.1",
        "--scheduler-port",
        "1",
    ]);
    cmd.timeout(std::time::Duration::from_secs(10));
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("credentials-config load failed"));
}

/// `--version` exits 0 (clap auto-derives). Catches the regression
/// shape where `#[command(...)]` defaults are accidentally dropped
/// in a future refactor of `ExecutorArgs`.
#[test]
fn version_flag_exits_zero() {
    let mut cmd = Command::cargo_bin("dataglot-ballista-executor").expect("binary built");
    cmd.arg("--version");
    cmd.assert().success();
}
