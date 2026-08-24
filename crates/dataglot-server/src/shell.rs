//! `dataglot shell` — an interactive SQL REPL over the embedded engine.
//!
//! Builds the same in-process session as `dataglot query` (federation +
//! plan-time governance, no pg-wire listener) once, then reads one statement
//! per line from stdin and prints results until EOF or `\q`. Results go to
//! stdout; the banner, prompt, and errors go to stderr, so a piped session's
//! stdout stays result-only.
//!
//! Dependency-free by design (no readline crate): line editing and history are
//! a shell / `rlwrap` concern, and pulling in `rustyline` would add a
//! dependency for marginal value over `dataglot query` + your shell's history.

use std::io::{BufRead, Write};

use anyhow::{Context, Result};

use crate::cli::{Args, ShellArgs};

/// Run the interactive shell.
///
/// # Errors
/// If the engine fails to initialize or stdin can't be read. A per-statement
/// query error is printed and the loop continues; only a fatal stdin I/O error
/// ends the shell non-zero.
// The `StdinLock` is deliberately held for the whole REPL — that's what a shell
// does — so the drop-tightening lint doesn't apply here.
#[allow(clippy::significant_drop_tightening)]
pub async fn run(args: &Args, s: &ShellArgs) -> Result<()> {
    let (_server, ctx) = crate::query::build_session(args, &s.user).await?;

    let mut stderr = std::io::stderr();
    let _ = writeln!(
        stderr,
        "dataglot shell — type SQL and press Enter; \\q or Ctrl-D to quit."
    );

    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        let _ = write!(stderr, "dataglot> ");
        let _ = stderr.flush();

        let Some(line) = lines.next() else {
            let _ = writeln!(stderr); // newline after the trailing prompt on EOF
            break;
        };
        let line = line.context("reading stdin")?;
        let sql = line.trim();
        if sql.is_empty() {
            continue;
        }
        if matches!(sql, "\\q" | "quit" | "exit") {
            break;
        }
        // Keep the REPL alive on a query error — print it and prompt again.
        if let Err(e) = crate::query::execute_and_print(&ctx, sql, s.format).await {
            let _ = writeln!(stderr, "error: {e:#}");
        }
    }
    Ok(())
}
