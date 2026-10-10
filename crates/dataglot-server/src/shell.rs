//! `dataglot shell` — an interactive SQL REPL over the embedded engine.
//!
//! Builds the same in-process session as `dataglot query` (federation +
//! plan-time governance under `--user`'s identity, no pg-wire listener) once,
//! then reads SQL from stdin and prints results until EOF or `\q`. As in psql,
//! a statement may span several lines and runs once it ends with `;`. Results
//! go to stdout; the banner, prompt, and errors go to stderr, so a piped
//! session's stdout stays result-only.
//!
//! Dependency-free by design (no readline crate): line editing and history are
//! a shell / `rlwrap` concern, and pulling in `rustyline` would add a
//! dependency for marginal value over `dataglot query` + your shell's history.

use std::io::{BufRead, Write};
use std::ops::Range;

use anyhow::{Context, Result};
use datafusion::sql::sqlparser::dialect::GenericDialect;
use datafusion::sql::sqlparser::tokenizer::{Location, Token, Tokenizer, TokenizerError};

use crate::cli::{Args, ShellArgs};

const PROMPT: &str = "dataglot> ";
// Same markers as psql, so it's obvious when a quote or comment is still open.
const CONTINUATION_PROMPT: &str = "dataglot-> ";
const IN_STRING_PROMPT: &str = "dataglot'> ";
const IN_IDENTIFIER_PROMPT: &str = "dataglot\"> ";
const IN_COMMENT_PROMPT: &str = "dataglot*> ";

/// Run the interactive shell.
///
/// # Errors
/// If the engine fails to initialize or stdin can't be read. A per-statement
/// query error is printed and the loop continues; only a fatal stdin I/O error
/// ends the shell non-zero.
pub async fn run(args: &Args, s: &ShellArgs) -> Result<()> {
    let session = crate::query::build_session(args, &s.user).await?;
    let stdin = std::io::stdin();
    repl(stdin.lock(), &mut std::io::stderr(), async |sql: &str| {
        session.execute_and_print(sql, s.format).await
    })
    .await
}

/// The read loop, generic over its input and prompt output so tests can drive
/// it without a terminal.
async fn repl<R, W, F>(mut input: R, stderr: &mut W, mut execute: F) -> Result<()>
where
    R: BufRead,
    W: Write,
    F: AsyncFnMut(&str) -> Result<()>,
{
    let _ = writeln!(
        stderr,
        "dataglot shell — end statements with `;`; \\q or Ctrl-D to quit."
    );

    let mut buffer = StatementBuffer::default();
    let mut raw = Vec::new();
    loop {
        let _ = write!(stderr, "{}", buffer.prompt());
        let _ = stderr.flush();

        raw.clear();
        if input.read_until(b'\n', &mut raw).context("reading stdin")? == 0 {
            // Finish the prompt line, then run whatever is left: piped scripts
            // often leave the `;` off their last statement.
            let _ = writeln!(stderr);
            if let Some(sql) = buffer.finish() {
                run_statement(&mut execute, &sql, stderr).await;
            }
            break;
        }
        // Read bytes rather than lines: a terminal in a legacy code page can
        // send a byte that isn't UTF-8, and that shouldn't end the session.
        // It turns into U+FFFD and the statement fails or runs as usual.
        let line = String::from_utf8_lossy(&raw);
        let line = line.trim_end_matches(['\n', '\r']);
        // Only at a fresh prompt: mid-statement, `exit` is just SQL text.
        if buffer.is_empty() && matches!(line.trim(), "\\q" | "quit" | "exit") {
            break;
        }
        for sql in buffer.push_line(line) {
            run_statement(&mut execute, &sql, stderr).await;
        }
    }
    Ok(())
}

async fn run_statement<F, W>(execute: &mut F, sql: &str, stderr: &mut W)
where
    F: AsyncFnMut(&str) -> Result<()>,
    W: Write,
{
    // A failing statement is reported, not fatal.
    if let Err(e) = execute(sql).await {
        let _ = writeln!(stderr, "error: {e:#}");
    }
}

/// Collects input lines and hands statements back as their `;` arrives.
///
/// Boundaries come from sqlparser's tokenizer with the generic dialect
/// DataFusion parses with, so a `;` inside a string, a quoted identifier or a
/// comment doesn't end a statement.
#[derive(Debug, Default)]
struct StatementBuffer {
    /// Input after the last complete statement. Kept empty unless it holds
    /// something besides whitespace and comments.
    pending: String,
    /// Set while `pending` ends inside a string, identifier or comment.
    open: Option<Open>,
}

impl StatementBuffer {
    fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    fn prompt(&self) -> &'static str {
        match self.open {
            Some(Open::String) => IN_STRING_PROMPT,
            Some(Open::QuotedIdentifier) => IN_IDENTIFIER_PROMPT,
            Some(Open::Comment) => IN_COMMENT_PROMPT,
            None if self.is_empty() => PROMPT,
            None => CONTINUATION_PROMPT,
        }
    }

    fn push_line(&mut self, line: &str) -> Vec<String> {
        self.pending.push_str(line);
        self.pending.push('\n');
        self.open = None;
        match scan(&self.pending) {
            Scan::Complete { statements, rest } => {
                let done = statements
                    .into_iter()
                    .map(|r| self.pending[r].trim().to_string())
                    .collect();
                self.pending = rest.map_or_else(String::new, |r| self.pending[r].to_string());
                done
            }
            // We can't find the boundaries, but once the user has typed a `;`
            // run it as is and let the planner report the problem, rather than
            // waiting for a terminator that will never parse.
            Scan::Unlexable if self.pending.trim_end().ends_with(';') => {
                vec![std::mem::take(&mut self.pending).trim().to_string()]
            }
            Scan::Incomplete(open) => {
                self.open = Some(open);
                Vec::new()
            }
            Scan::Unlexable => Vec::new(),
        }
    }

    /// Whatever is left at end of input, unterminated or not.
    fn finish(&mut self) -> Option<String> {
        self.open = None;
        let rest = std::mem::take(&mut self.pending);
        let sql = rest.trim();
        (!sql.is_empty()).then(|| sql.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Open {
    String,
    QuotedIdentifier,
    Comment,
}

enum Scan {
    /// Input ends inside a string, quoted identifier or block comment.
    Incomplete(Open),
    /// Byte ranges of the finished statements (without their `;`), plus the
    /// trailing text if it holds more than whitespace and comments.
    Complete {
        statements: Vec<Range<usize>>,
        rest: Option<Range<usize>>,
    },
    /// The tokenizer rejected the input for some other reason.
    Unlexable,
}

fn scan(sql: &str) -> Scan {
    let tokens = match Tokenizer::new(&GenericDialect {}, sql).tokenize_with_location() {
        Ok(tokens) => tokens,
        Err(e) => return unterminated(&e).map_or(Scan::Unlexable, Scan::Incomplete),
    };

    let mut statements = Vec::new();
    let mut start = 0;
    let mut has_content = false;
    for t in &tokens {
        match t.token {
            Token::SemiColon => {
                let end = byte_offset(sql, t.span.start);
                if has_content {
                    statements.push(start..end);
                }
                start = end + 1;
                has_content = false;
            }
            // Comments are whitespace tokens too.
            Token::Whitespace(_) | Token::EOF => {}
            _ => has_content = true,
        }
    }
    Scan::Complete {
        statements,
        rest: has_content.then_some(start..sql.len()),
    }
}

/// What the input was still inside of when the tokenizer ran out, if that's
/// why it failed. sqlparser has no error kind for this, so it goes by the
/// message; the `waits_for_*` tests catch it if an upgrade rewords them.
fn unterminated(e: &TokenizerError) -> Option<Open> {
    let msg = e.message.as_str();
    if msg.contains("multi-line comment") {
        Some(Open::Comment)
    } else if msg.contains("close delimiter") {
        Some(Open::QuotedIdentifier)
    } else if msg.starts_with("Unterminated") || msg.contains("EOF") {
        Some(Open::String)
    } else {
        None
    }
}

/// Tokenizer locations are 1-based line / character columns; map one back to a
/// byte offset into `sql`.
fn byte_offset(sql: &str, loc: Location) -> usize {
    let line_start: usize = sql
        .split_inclusive('\n')
        .take((loc.line as usize).saturating_sub(1))
        .map(str::len)
        .sum();
    sql[line_start..]
        .char_indices()
        .nth((loc.column as usize).saturating_sub(1))
        .map_or(sql.len(), |(i, _)| line_start + i)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// Feed `lines` through a fresh buffer; returns every statement it
    /// completed and what `finish` gives back afterwards.
    fn feed(lines: &[&str]) -> (Vec<String>, Option<String>) {
        let mut buf = StatementBuffer::default();
        let done = lines.iter().flat_map(|l| buf.push_line(l)).collect();
        (done, buf.finish())
    }

    #[test]
    fn single_line_statement() {
        assert_eq!(feed(&["SELECT 1;"]), (vec!["SELECT 1".to_string()], None));
    }

    #[test]
    fn statement_across_lines() {
        let (done, rest) = feed(&["SELECT id,", "  email", "FROM t", ";"]);
        assert_eq!(done, ["SELECT id,\n  email\nFROM t"]);
        assert_eq!(rest, None);
    }

    #[test]
    fn several_statements_on_one_line() {
        let (done, rest) = feed(&["SELECT 1; SELECT 2;SELECT 3"]);
        assert_eq!(done, ["SELECT 1", "SELECT 2"]);
        assert_eq!(rest.as_deref(), Some("SELECT 3"));
    }

    #[test]
    fn semicolon_inside_quotes_or_comments_does_not_split() {
        let (done, _) = feed(&[
            "SELECT 'a;b', 'it''s; fine' AS \"x;y\" -- trailing; comment",
            "FROM t /* also; */;",
        ]);
        assert_eq!(done.len(), 1, "got {done:?}");
        assert!(done[0].starts_with("SELECT 'a;b'"));
        assert!(done[0].ends_with("/* also; */"));
    }

    #[test]
    fn waits_for_unterminated_string() {
        let mut buf = StatementBuffer::default();
        assert!(buf.push_line("SELECT 'open;").is_empty());
        assert_eq!(buf.prompt(), IN_STRING_PROMPT);
        assert_eq!(
            buf.push_line("still open';"),
            ["SELECT 'open;\nstill open'"]
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn waits_for_unterminated_quoted_identifier() {
        let mut buf = StatementBuffer::default();
        assert!(buf.push_line("SELECT 1 AS \"a;").is_empty());
        assert_eq!(buf.prompt(), IN_IDENTIFIER_PROMPT);
        assert_eq!(buf.push_line("b\";"), ["SELECT 1 AS \"a;\nb\""]);
    }

    #[test]
    fn waits_for_unterminated_block_comment() {
        let mut buf = StatementBuffer::default();
        assert!(buf.push_line("SELECT 1 /* a;").is_empty());
        assert_eq!(buf.prompt(), IN_COMMENT_PROMPT);
        assert_eq!(buf.push_line("b; */ ;"), ["SELECT 1 /* a;\nb; */"]);
    }

    #[test]
    fn prompt_follows_what_is_still_open() {
        let mut buf = StatementBuffer::default();
        assert_eq!(buf.prompt(), PROMPT);
        buf.push_line("SELECT");
        assert_eq!(buf.prompt(), CONTINUATION_PROMPT);
        buf.push_line("  'abc");
        assert_eq!(buf.prompt(), IN_STRING_PROMPT);
        buf.push_line("' AS \"x");
        assert_eq!(buf.prompt(), IN_IDENTIFIER_PROMPT);
        buf.push_line("\" /* note");
        assert_eq!(buf.prompt(), IN_COMMENT_PROMPT);
        buf.push_line("*/");
        assert_eq!(buf.prompt(), CONTINUATION_PROMPT);
        assert_eq!(buf.push_line(";").len(), 1);
        assert_eq!(buf.prompt(), PROMPT);
    }

    #[test]
    fn blank_and_comment_only_input_leaves_the_prompt_fresh() {
        let mut buf = StatementBuffer::default();
        for line in ["", "   ", "-- just a note", ";;", "/* x */ ;"] {
            assert!(buf.push_line(line).is_empty(), "{line:?}");
            assert!(buf.is_empty(), "{line:?} left {:?}", buf.pending);
        }
        assert_eq!(buf.finish(), None);
    }

    #[test]
    fn unlexable_input_runs_once_a_semicolon_arrives() {
        // A bad unicode escape is rejected by the tokenizer itself. It should
        // reach the planner (and its error message) instead of hanging.
        let mut buf = StatementBuffer::default();
        assert!(buf.push_line(r"SELECT U&'\zz'").is_empty());
        assert_eq!(buf.push_line(";"), ["SELECT U&'\\zz'\n;"]);
        assert!(buf.is_empty());
    }

    #[test]
    fn handles_multibyte_text() {
        let (done, _) = feed(&["SELECT 'é→ü'; SELECT '日本';"]);
        assert_eq!(done, ["SELECT 'é→ü'", "SELECT '日本'"]);
    }

    #[test]
    fn finish_returns_an_unterminated_tail() {
        assert_eq!(
            feed(&["SELECT", "1"]),
            (vec![], Some("SELECT\n1".to_string()))
        );
    }

    /// Drive `repl` with `input`, recording what it executes. Statements whose
    /// text starts with `FAIL` return an error.
    async fn drive(input: impl AsRef<[u8]>) -> (Vec<String>, String) {
        let mut ran = Vec::new();
        let mut stderr = Vec::new();
        repl(
            Cursor::new(input.as_ref()),
            &mut stderr,
            async |sql: &str| {
                ran.push(sql.to_string());
                if sql.starts_with("FAIL") {
                    anyhow::bail!("boom");
                }
                Ok(())
            },
        )
        .await
        .expect("repl");
        (ran, String::from_utf8(stderr).expect("utf-8"))
    }

    #[tokio::test]
    async fn repl_runs_statements_in_order_and_stops_at_quit() {
        let (ran, _) = drive("SELECT\n1;\nSELECT 2; SELECT 3;\n\\q\nSELECT 4;\n").await;
        assert_eq!(ran, ["SELECT\n1", "SELECT 2", "SELECT 3"]);
    }

    #[tokio::test]
    async fn repl_treats_quit_words_as_sql_mid_statement() {
        let (ran, _) = drive("SELECT\nexit\n;\nquit\n").await;
        assert_eq!(ran, ["SELECT\nexit"]);
    }

    #[tokio::test]
    async fn repl_keeps_going_after_an_error() {
        let (ran, stderr) = drive("FAIL 1;\nSELECT 2;\n").await;
        assert_eq!(ran, ["FAIL 1", "SELECT 2"]);
        assert!(stderr.contains("error: boom"), "{stderr}");
    }

    #[tokio::test]
    async fn repl_runs_the_last_statement_without_a_semicolon_at_eof() {
        let (ran, _) = drive("SELECT 1;\nSELECT\n2").await;
        assert_eq!(ran, ["SELECT 1", "SELECT\n2"]);
    }

    /// `SELECT 'abc'` then `';` opens a second string, so the `\q` after it
    /// is string content. The prompt has to say so.
    #[tokio::test]
    async fn repl_shows_when_input_is_inside_a_string() {
        let (ran, stderr) = drive("SELECT 'abc'\n';\n\\q\n").await;
        assert!(
            stderr.contains(&format!(
                "{PROMPT}{CONTINUATION_PROMPT}{IN_STRING_PROMPT}{IN_STRING_PROMPT}"
            )),
            "{stderr:?}"
        );
        // Nothing ran until end of input flushed the unterminated statement.
        assert_eq!(ran, ["SELECT 'abc'\n';\n\\q"]);
    }

    #[tokio::test]
    async fn repl_survives_input_that_is_not_utf8() {
        // 0xB4 is `´` in Latin-1 / CP1252, which a Windows terminal can send.
        let (ran, _) = drive(b"SELECT 'a\xb4b';\nSELECT 1;\n").await;
        assert_eq!(ran, ["SELECT 'a\u{fffd}b'", "SELECT 1"]);
    }

    #[tokio::test]
    async fn repl_accepts_crlf_line_endings() {
        let (ran, _) = drive("SELECT\r\n1;\r\n\\q\r\nSELECT 2;\r\n").await;
        assert_eq!(ran, ["SELECT\n1"]);
    }

    #[tokio::test]
    async fn repl_shows_the_continuation_prompt_mid_statement() {
        let (_, stderr) = drive("SELECT\n1;\n").await;
        assert!(
            stderr.contains(&format!("{PROMPT}{CONTINUATION_PROMPT}{PROMPT}")),
            "{stderr:?}"
        );
    }

    /// The real engine behind the loop: a multi-line statement with a `;` in a
    /// string literal plans and returns the right row.
    #[tokio::test]
    async fn repl_executes_multiline_sql_against_the_embedded_engine() {
        use clap::Parser;

        let args = Args::try_parse_from(["dataglot"]).expect("parse default args");
        let session = crate::query::build_session(&args, "dataglot")
            .await
            .expect("build session");
        let mut rendered = String::new();
        let mut stderr = Vec::new();
        repl(
            Cursor::new("SELECT\n  41 + 1 AS n,\n  'a;b' AS s\n;\n"),
            &mut stderr,
            async |sql: &str| {
                let batches = session.execute(sql).await?;
                rendered.push_str(
                    &datafusion::arrow::util::pretty::pretty_format_batches(&batches)?.to_string(),
                );
                Ok(())
            },
        )
        .await
        .expect("repl");
        assert!(rendered.contains("| 42 | a;b |"), "{rendered}");
    }
}
