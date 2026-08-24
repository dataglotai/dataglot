//! Quote-aware splitting of a multi-statement simple-query message.
//!
//! A single pg wire simple-query message may bundle several statements
//! separated by `;` (`psql -c "…;…"`, JDBC `executeUpdate` with multiple
//! statements). `datafusion-postgres` splits ordinary multi-statement messages
//! internally, but the control-plane DDL parsers ([`crate::catalog_ddl`],
//! [`crate::secret_ddl`], [`crate::user_ddl`], [`crate::policy_ddl`]) decline
//! anything after their single statement — so a message like
//! `CREATE CATALOG c WITH (…); SELECT … FROM c…` never routes to the admin seam
//! and instead falls through to a planner that cannot parse `CREATE CATALOG`.
//!
//! [`split_sql_statements`] splits on top-level `;` while honouring the *exact*
//! quoting rules the DDL parsers use (see `catalog_ddl::parse_quoted`): a `;`
//! inside a single- or double-quoted string is **not** a separator, and a
//! doubled quote (`''` / `""`) inside a quoted string is an escaped literal
//! quote, not a close — so a `;` buried in a DSN or password value never
//! splits the message.

/// Split a simple-query string into its top-level statements.
///
/// Splits on `;` that are **not** inside a single- or double-quoted string.
/// A doubled quote (`''` / `""`) inside a quoted string is an escaped literal
/// quote and does not close it — matching the DDL parsers' quoting. Each
/// returned statement is trimmed; empty (whitespace-only) statements — such as
/// the tail after a trailing `;` — are dropped. A message with no top-level
/// `;` yields exactly one element (the trimmed input) when non-empty.
///
/// UTF-8 safe: quotes and `;` are ASCII, so the byte scan only ever slices at
/// ASCII boundaries; multi-byte characters inside statements are passed over
/// untouched.
#[must_use]
pub(crate) fn split_sql_statements(query: &str) -> Vec<&str> {
    let bytes = query.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    // `Some(q)` while inside a string opened by quote byte `q` (`'` or `"`).
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == q {
                    if bytes.get(i + 1) == Some(&q) {
                        // Doubled quote: an escaped literal quote, still inside
                        // the string. Consume both bytes.
                        i += 2;
                        continue;
                    }
                    quote = None;
                }
                i += 1;
            }
            None => match b {
                b'\'' | b'"' => {
                    quote = Some(b);
                    i += 1;
                }
                b';' => {
                    let stmt = query[start..i].trim();
                    if !stmt.is_empty() {
                        out.push(stmt);
                    }
                    i += 1;
                    start = i;
                }
                _ => i += 1,
            },
        }
    }
    let tail = query[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_simple_multi_statement() {
        assert_eq!(split_sql_statements("a; b; c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn single_statement_is_one_element() {
        assert_eq!(split_sql_statements("SELECT 1"), vec!["SELECT 1"]);
        // A statement with no top-level `;` stays whole even with inner spaces.
        assert_eq!(
            split_sql_statements("SELECT * FROM t WHERE a = 1"),
            vec!["SELECT * FROM t WHERE a = 1"]
        );
    }

    #[test]
    fn semicolon_inside_single_quotes_does_not_split() {
        assert_eq!(
            split_sql_statements("CREATE CATALOG c WITH (dsn = 'host=db;port=5432'); SELECT 1"),
            vec![
                "CREATE CATALOG c WITH (dsn = 'host=db;port=5432')",
                "SELECT 1"
            ]
        );
    }

    #[test]
    fn semicolon_inside_double_quotes_does_not_split() {
        assert_eq!(
            split_sql_statements(r#"CREATE CATALOG "a;b" WITH (); SELECT 1"#),
            vec![r#"CREATE CATALOG "a;b" WITH ()"#, "SELECT 1"]
        );
    }

    #[test]
    fn doubled_quote_escape_stays_one_token() {
        // The doubled '' is an escaped quote, so the ; after it is still inside
        // the string — the whole thing is a single statement.
        assert_eq!(split_sql_statements("'a'';''b'"), vec!["'a'';''b'"]);
    }

    #[test]
    fn trailing_semicolon_and_empty_tail_dropped() {
        assert_eq!(split_sql_statements("SELECT 1;"), vec!["SELECT 1"]);
        assert_eq!(split_sql_statements("SELECT 1;   "), vec!["SELECT 1"]);
        // Empty statements between separators are dropped too.
        assert_eq!(
            split_sql_statements("SELECT 1;;SELECT 2"),
            vec!["SELECT 1", "SELECT 2"]
        );
    }

    #[test]
    fn empty_and_whitespace_yield_no_statements() {
        assert!(split_sql_statements("").is_empty());
        assert!(split_sql_statements("   ").is_empty());
        assert!(split_sql_statements(";").is_empty());
        assert!(split_sql_statements(" ; ; ").is_empty());
    }

    #[test]
    fn utf8_content_is_preserved() {
        // Multi-byte characters inside a statement/value survive the byte scan.
        assert_eq!(
            split_sql_statements("SELECT 'café'; SELECT 'naïve'"),
            vec!["SELECT 'café'", "SELECT 'naïve'"]
        );
    }
}
