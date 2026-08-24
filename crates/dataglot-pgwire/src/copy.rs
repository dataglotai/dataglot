//! `COPY (query) TO STDOUT` egress — text format.
//!
//! `COPY … TO STDOUT` is the standard PostgreSQL bulk-export path (psql
//! `\copy`, ETL tools). Neither DataFusion's parser nor `datafusion-postgres`
//! accepts it (`STDOUT` isn't a string literal), so we intercept it at the
//! pg-wire boundary — the same seam as the `SHOW` / `TABLE` rewrite shims —
//! run the inner query, and stream the result as PostgreSQL COPY **text**
//! format (tab-delimited, `\N` for NULL, backslash-escaped), returned as
//! [`Response::CopyOut`]. The pgwire server then drives the
//! `CopyOutResponse` → `CopyData`* → `CopyDone` → `CommandComplete` sequence.
//!
//! Text (COPY's default) only for now; CSV / binary `WITH` options and
//! `COPY … FROM STDIN` ingest are follow-ups on.

use std::sync::Arc;

use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::error::ArrowError;
use datafusion::arrow::util::display::{ArrayFormatter, FormatOptions};
use datafusion::prelude::SessionContext;
use futures::StreamExt;
use pgwire::api::results::{CopyResponse, Response};
use pgwire::error::{PgWireError, PgWireResult};
use pgwire::messages::copy::CopyData;

/// If `query` is a `COPY … TO STDOUT` statement we can serve, return the
/// `SELECT` to execute; otherwise `None` (the caller passes it through
/// unchanged).
///
/// Accepts `COPY (<query>) TO STDOUT` and `COPY <table> TO STDOUT`; a trailing
/// `;` is tolerated. A `WITH (...)` clause (CSV / binary / options) is
/// **declined** for now — text is the only supported format — so those
/// statements fall through rather than being silently mis-encoded.
#[must_use]
pub fn detect_copy_to_stdout(query: &str) -> Option<String> {
    let mut s = query.trim();
    if let Some(stripped) = s.strip_suffix(';') {
        s = stripped.trim_end();
    }
    // `COPY` + whitespace, case-insensitive; `get`/`as_bytes().get` keep this
    // panic-free on non-ASCII input.
    if !s.get(..4).is_some_and(|h| h.eq_ignore_ascii_case("copy")) {
        return None;
    }
    if !s.as_bytes().get(4).is_some_and(u8::is_ascii_whitespace) {
        return None;
    }
    let body = s[4..].trim();

    // Split off a trailing `TO STDOUT` (case-insensitive). Use the *last*
    // match so a parenthesised inner query containing those words is preserved.
    let lower = body.to_ascii_lowercase();
    let pos = lower.rfind("to stdout")?;
    // Only whitespace may follow — decline `WITH (...)` etc. for now.
    if !body[pos + "to stdout".len()..].trim().is_empty() {
        return None;
    }
    let target = body[..pos].trim();
    if let Some(inner) = target.strip_prefix('(').and_then(|t| t.strip_suffix(')')) {
        let inner = inner.trim();
        (!inner.is_empty()).then(|| inner.to_string())
    } else if !target.is_empty() && !target.contains('(') {
        // `COPY <table> TO STDOUT` — a bare relation name.
        Some(format!("SELECT * FROM {target}"))
    } else {
        None
    }
}

/// COPY text-format escaping (PostgreSQL rules): backslash, tab, newline, CR.
fn escape_into(field: &str, out: &mut String) {
    for c in field.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
}

/// Encode one `RecordBatch` as PostgreSQL COPY text: one line per row, columns
/// tab-delimited, `\N` for NULL, special characters backslash-escaped.
fn batch_to_copy_text(batch: &RecordBatch) -> Result<CopyData, ArrowError> {
    let opts = FormatOptions::default();
    let fmts: Vec<ArrayFormatter> = batch
        .columns()
        .iter()
        .map(|c| ArrayFormatter::try_new(c, &opts))
        .collect::<Result<_, _>>()?;
    let mut out = String::new();
    for row in 0..batch.num_rows() {
        for (col_idx, col) in batch.columns().iter().enumerate() {
            if col_idx > 0 {
                out.push('\t');
            }
            if col.is_null(row) {
                out.push_str("\\N");
            } else {
                escape_into(&fmts[col_idx].value(row).to_string(), &mut out);
            }
        }
        out.push('\n');
    }
    Ok(CopyData::new(out.into_bytes().into()))
}

/// Run `inner_query` and return a [`Response::CopyOut`] that streams its result
/// as COPY text. Per-batch execution errors surface inside the stream.
///
/// # Errors
/// Returns a [`PgWireError`] if planning `inner_query` or building its execution
/// stream fails (e.g. a syntax error or unknown table in the COPY sub-query).
pub async fn build_copy_out_response(
    ctx: &Arc<SessionContext>,
    inner_query: &str,
) -> PgWireResult<Response> {
    let df = ctx
        .sql(inner_query)
        .await
        .map_err(|e| PgWireError::ApiError(Box::new(e)))?;
    let stream = df
        .execute_stream()
        .await
        .map_err(|e| PgWireError::ApiError(Box::new(e)))?;
    let columns = stream.schema().fields().len();

    let data = stream.map(|batch| {
        batch
            .map_err(|e| PgWireError::ApiError(Box::new(e)))
            .and_then(|b| batch_to_copy_text(&b).map_err(|e| PgWireError::ApiError(Box::new(e))))
    });

    // format code 0 = text.
    Ok(Response::CopyOut(CopyResponse::new(0, columns, data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_parenthesised_query() {
        assert_eq!(
            detect_copy_to_stdout("COPY (SELECT 1) TO STDOUT"),
            Some("SELECT 1".to_string())
        );
        assert_eq!(
            detect_copy_to_stdout("  copy ( SELECT a, b FROM t ) to stdout ;  "),
            Some("SELECT a, b FROM t".to_string())
        );
    }

    #[test]
    fn detects_bare_table() {
        assert_eq!(
            detect_copy_to_stdout("COPY users TO STDOUT"),
            Some("SELECT * FROM users".to_string())
        );
        assert_eq!(
            detect_copy_to_stdout("COPY pg.public.orders TO STDOUT"),
            Some("SELECT * FROM pg.public.orders".to_string())
        );
    }

    #[test]
    fn declines_unsupported_and_unrelated() {
        // WITH options (CSV/binary) not supported yet — fall through.
        assert_eq!(
            detect_copy_to_stdout("COPY (SELECT 1) TO STDOUT WITH (FORMAT csv)"),
            None
        );
        // FROM STDIN (ingest) is a separate path.
        assert_eq!(detect_copy_to_stdout("COPY t FROM STDIN"), None);
        // COPY to a file is a server-side path we don't serve here.
        assert_eq!(detect_copy_to_stdout("COPY t TO '/tmp/x.csv'"), None);
        // Not a COPY at all.
        assert_eq!(detect_copy_to_stdout("SELECT 1"), None);
        assert_eq!(detect_copy_to_stdout("COPYt TO STDOUT"), None);
    }

    #[test]
    fn escaping_matches_copy_text_rules() {
        let mut out = String::new();
        escape_into("a\tb\\c\nd", &mut out);
        assert_eq!(out, "a\\tb\\\\c\\nd");
    }

    /// End-to-end of the core path: run a real query through a `SessionContext`
    /// and drain the `CopyOut` stream — proving detect → execute → text-encode →
    /// stream, incl. NULL → `\N`. (The pg-wire framing of `Response::CopyOut`
    /// into `CopyData` messages is the pgwire server's tested responsibility.)
    #[tokio::test]
    async fn copy_out_streams_query_result_as_text() {
        use datafusion::arrow::array::{Int32Array, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::datasource::MemTable;

        let schema = Arc::new(Schema::new(vec![
            Field::new("n", DataType::Int32, false),
            Field::new("s", DataType::Utf8, true),
        ]));
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int32Array::from(vec![1, 2])),
                Arc::new(StringArray::from(vec![Some("a"), None])),
            ],
        )
        .expect("batch builds");
        let ctx = Arc::new(SessionContext::new());
        ctx.register_table(
            "t",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).expect("memtable")),
        )
        .expect("register table");

        let inner = detect_copy_to_stdout("COPY (SELECT n, s FROM t ORDER BY n) TO STDOUT")
            .expect("statement detected");
        let resp = build_copy_out_response(&ctx, &inner)
            .await
            .expect("copy-out response");
        let Response::CopyOut(mut copy) = resp else {
            panic!("expected a CopyOut response");
        };

        let mut bytes = Vec::new();
        while let Some(chunk) = copy.data_stream().next().await {
            bytes.extend_from_slice(chunk.expect("copy chunk").data.as_ref());
        }
        // Row 1: `1\ta`; row 2 has a NULL string → `\N`.
        assert_eq!(String::from_utf8(bytes).expect("utf-8"), "1\ta\n2\t\\N\n");
    }
}
