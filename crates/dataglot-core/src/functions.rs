//! Compatibility scalar functions registered on every session.
//!
//! DataFusion ships the `%` operator for modulo but no `mod(a, b)`
//! *function*. `MOD` is SQL-standard and present in both Trino and
//! Postgres, so queries ported from either fail on Dataglot with
//! `Invalid function 'mod'`. [`mod_udf`] registers a thin `mod` alias
//! that delegates to Arrow's numeric remainder kernel — the same
//! computation the `%` operator performs.
//!
//! [`current_database_udf`] is a per-*session* function: it returns the
//! catalog name the connection is scoped to (Model A: catalog-as-
//! database), overriding `datafusion-pg-catalog`'s hardcoded
//! `"datafusion"`. Unlike `mod`, it's registered by the pgwire
//! `StartupObserver` once the `database` startup parameter is known, not
//! by the base session factory.

use std::sync::Arc;

use datafusion::arrow::array::{Array, ArrayRef, BooleanArray, StringArray, StringBuilder};
use datafusion::arrow::compute::kernels::numeric::rem;
use datafusion::arrow::datatypes::DataType;
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::logical_expr::{
    create_udf, ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature,
    TypeSignature, Volatility,
};

/// `mod(a, b)` — modulo, an alias for the `%` operator. Accepts two
/// numeric arguments (integer or floating point); both are coerced to a
/// common type and the result takes that type, matching `%`.
#[derive(Debug, PartialEq, Eq, Hash)]
struct ModUdf {
    signature: Signature,
}

impl ModUdf {
    fn new() -> Self {
        Self {
            // Both args coerce to a single common numeric type. Int64
            // covers integer modulo; Float64 covers the rest (and mixed
            // int/float promotes to Float64), matching the `%` operator.
            signature: Signature::uniform(
                2,
                vec![DataType::Int64, DataType::Float64],
                Volatility::Immutable,
            ),
        }
    }
}

impl ScalarUDFImpl for ModUdf {
    // The `ScalarUDFImpl::name` trait signature ties the return lifetime
    // to `&self`, so we can't widen to `&'static str` as clippy suggests.
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "mod"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, arg_types: &[DataType]) -> DfResult<DataType> {
        // After coercion both args share a type; the remainder takes it.
        Ok(arg_types[0].clone())
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DfResult<ColumnarValue> {
        let arrays: Vec<ArrayRef> = ColumnarValue::values_to_arrays(&args.args)?;
        let result = rem(&arrays[0], &arrays[1])?;
        Ok(ColumnarValue::Array(result))
    }
}

/// Build the `mod` scalar UDF for registration on a `SessionContext`.
#[must_use]
pub fn mod_udf() -> ScalarUDF {
    ScalarUDF::from(ModUdf::new())
}

/// Build a `current_database()` scalar UDF that returns `database` — the
/// catalog this connection is scoped to (Model A: catalog-as-database).
///
/// `datafusion-pg-catalog`'s built-in `current_database()` hardcodes
/// `"datafusion"` regardless of the connection's `database` startup
/// parameter. Because DataFusion's `register_udf` replaces a UDF
/// by name, registering this per-session — from the pgwire
/// `StartupObserver`, once the resolved catalog name is known — shadows
/// the upstream one so `SELECT current_database()` reflects what the
/// client connected with.
///
/// Postgres fixes `current_database()` for the life of a connection
/// (switching databases means reconnecting), so a per-session UDF that
/// closes over the resolved name is the natural fit — no plan-time
/// substitution, no per-row lookup. Marked `Stable`: constant within a
/// session, not across.
#[must_use]
pub fn current_database_udf(database: &str) -> ScalarUDF {
    let database = database.to_string();
    // Zero-arg like Postgres `current_database()`; returns the captured
    // name as a single-element Utf8 array (mirrors the upstream impl's
    // shape, just with the right value).
    let func = move |_args: &[ColumnarValue]| {
        let mut builder = StringBuilder::new();
        builder.append_value(&database);
        let array: ArrayRef = Arc::new(builder.finish());
        Ok(ColumnarValue::Array(array))
    };
    create_udf(
        "current_database",
        vec![],
        DataType::Utf8,
        Volatility::Stable,
        Arc::new(func),
    )
}

/// Build a `session_user` / `current_user` scalar UDF returning `user` — the
/// role this connection authenticated as (the pgwire startup `user` parameter).
///
/// `datafusion-pg-catalog`'s built-in `session_user` hardcodes `"postgres"`
/// (a `// TODO: return real user`), and it SQL-rewrites `current_user` →
/// `session_user`, so both report the constant. Registering these per-session —
/// from the pgwire `StartupObserver` once the startup `user` is known, mirroring
/// [`current_database_udf`], or from the embedded `dataglot query`/`shell` path,
/// which never gets that pg-catalog rewrite — makes `SELECT current_user` /
/// `session_user` reflect who actually connected. `register_udf` replaces by
/// name, so this shadows the upstream one. Marked `Stable`: fixed for the life
/// of a connection.
fn user_identity_udf(name: &str, user: &str) -> ScalarUDF {
    let user = user.to_string();
    let func = move |_args: &[ColumnarValue]| {
        let mut builder = StringBuilder::new();
        builder.append_value(&user);
        let array: ArrayRef = Arc::new(builder.finish());
        Ok(ColumnarValue::Array(array))
    };
    create_udf(
        name,
        vec![],
        DataType::Utf8,
        Volatility::Stable,
        Arc::new(func),
    )
}

/// `session_user()` → the connecting role. See `user_identity_udf`.
#[must_use]
pub fn session_user_udf(user: &str) -> ScalarUDF {
    user_identity_udf("session_user", user)
}

/// `current_user()` → the connecting role. See `user_identity_udf`.
///
/// Over pgwire, `datafusion-pg-catalog` SQL-rewrites `current_user` →
/// `session_user`; the embedded `ctx.sql()` path (`dataglot query`/`shell`) has
/// no such rewrite, so register this alongside [`session_user_udf`] to make
/// `SELECT current_user` / `CURRENT_USER` resolve there too.
#[must_use]
pub fn current_user_udf(user: &str) -> ScalarUDF {
    user_identity_udf("current_user", user)
}

/// Shared builder for the `pg_*_is_visible(oid) -> bool` shims.
///
/// psql filters its `\dt` / `\df` / `\dT` listings with
/// `pg_table_is_visible` / `pg_function_is_visible` / `pg_type_is_visible`
/// — "is this object on the search path?". Dataglot's `pg_catalog`
/// emulation doesn't model per-session search paths beyond the default
/// schema, and every object it lists is already scoped to the
/// connection's catalog, so visibility is uniformly `true`. The
/// argument (`oid`) arrives as whatever the emulation uses for oids;
/// accept `Int64` (the widest common shape) — DataFusion coerces
/// smaller ints.
fn is_visible_udf(name: &str) -> ScalarUDF {
    let func = move |args: &[ColumnarValue]| {
        let rows = match args.first() {
            Some(ColumnarValue::Array(a)) => a.len(),
            _ => 1,
        };
        let array: ArrayRef = Arc::new(datafusion::arrow::array::BooleanArray::from(vec![
            true;
            rows
        ]));
        Ok(ColumnarValue::Array(array))
    };
    create_udf(
        name,
        vec![DataType::Int64],
        DataType::Boolean,
        Volatility::Stable,
        Arc::new(func),
    )
}

/// `pg_table_is_visible(oid) -> bool`, always `true`.
///
/// psql's `\dt` (v16+) filters its `pg_class` listing with
/// `pg_table_is_visible(c.oid)`. Without it `\dt` fails with
/// `Invalid function 'pg_table_is_visible'`.
#[must_use]
pub fn pg_table_is_visible_udf() -> ScalarUDF {
    is_visible_udf("pg_table_is_visible")
}

/// `pg_function_is_visible(oid) -> bool`, always `true`.
///
/// psql's `\df` filters `pg_proc` with `pg_function_is_visible(p.oid)`.
/// `datafusion-pg-catalog` doesn't provide this one, so `\df` fails in
/// **both** single-node and distributed mode without this shim — the
/// same always-`true` pattern RisingWave uses for its visibility fns.
#[must_use]
pub fn pg_function_is_visible_udf() -> ScalarUDF {
    is_visible_udf("pg_function_is_visible")
}

/// `pg_type_is_visible(oid) -> bool`, always `true`.
///
/// psql's `\dT` filters `pg_type` with `pg_type_is_visible(t.oid)`.
/// Not provided by `datafusion-pg-catalog`; without this shim `\dT`
/// fails in both modes.
#[must_use]
pub fn pg_type_is_visible_udf() -> ScalarUDF {
    is_visible_udf("pg_type_is_visible")
}

/// Shared builder for `<name>(oid) -> text` shims that return the empty string
/// for any oid.
///
/// psql's `\df` selects `pg_get_function_result(p.oid)` and
/// `pg_get_function_arguments(p.oid)` to render a function's result/argument
/// types. Dataglot's `pg_proc` emulation lists no user functions, so these are
/// never invoked for a real row — but the functions must *exist* for the `\df`
/// query to plan, else it fails with `Invalid function 'pg_get_function_result'`
///. Same always-safe shim shape as the `pg_*_is_visible` fns.
fn empty_text_for_oid_udf(name: &str) -> ScalarUDF {
    let func = move |args: &[ColumnarValue]| {
        let rows = match args.first() {
            Some(ColumnarValue::Array(a)) => a.len(),
            _ => 1,
        };
        // Vectorized construction (mirrors is_visible_udf's BooleanArray::from).
        let array: ArrayRef = Arc::new(StringArray::from(vec![""; rows]));
        Ok(ColumnarValue::Array(array))
    };
    create_udf(
        name,
        vec![DataType::Int64],
        DataType::Utf8,
        Volatility::Stable,
        Arc::new(func),
    )
}

/// `pg_get_function_result(oid) -> text` — empty shim so psql `\df` plans.
#[must_use]
pub fn pg_get_function_result_udf() -> ScalarUDF {
    empty_text_for_oid_udf("pg_get_function_result")
}

/// `pg_get_function_arguments(oid) -> text` — empty shim so psql `\df` plans.
#[must_use]
pub fn pg_get_function_arguments_udf() -> ScalarUDF {
    empty_text_for_oid_udf("pg_get_function_arguments")
}

/// Shared builder for object-comment shims that return SQL NULL.
///
/// Dataglot stores no object comments, so `obj_description` / `shobj_description`
/// (psql `\dT`, `\d+`) and `col_description` (psql `\d+` column comments) return
/// NULL for every object. Without them those meta-commands fail with
/// `Invalid function 'obj_description'`.
fn null_comment_udf(name: &str, args: Vec<DataType>) -> ScalarUDF {
    let func = move |a: &[ColumnarValue]| {
        // Size the output by the longest array argument, not just the first — a
        // call like `col_description(1, col)` has a scalar first arg and a column
        // second arg, and must return one row per input row (scalars broadcast).
        let rows = a
            .iter()
            .filter_map(|v| match v {
                ColumnarValue::Array(x) => Some(x.len()),
                ColumnarValue::Scalar(_) => None,
            })
            .max()
            .unwrap_or(1);
        // Vectorized all-NULL column of the right length.
        let array: ArrayRef = Arc::new(StringArray::new_null(rows));
        Ok(ColumnarValue::Array(array))
    };
    create_udf(
        name,
        args,
        DataType::Utf8,
        Volatility::Stable,
        Arc::new(func),
    )
}

/// `obj_description(oid, catalog text) -> text` (always NULL) — psql `\dT` / `\d+`
/// object comments.
#[must_use]
pub fn obj_description_udf() -> ScalarUDF {
    null_comment_udf("obj_description", vec![DataType::Int64, DataType::Utf8])
}

/// `shobj_description(oid, catalog text) -> text` (always NULL).
#[must_use]
pub fn shobj_description_udf() -> ScalarUDF {
    null_comment_udf("shobj_description", vec![DataType::Int64, DataType::Utf8])
}

/// `col_description(oid, column int) -> text` (always NULL) — psql `\d+` column
/// comments.
#[must_use]
pub fn col_description_udf() -> ScalarUDF {
    null_comment_udf("col_description", vec![DataType::Int64, DataType::Int64])
}

/// Build a `dataglot_execution_mode()` scalar UDF that returns `mode` —
/// how this server executes queries: `"single-node"`, or
/// `"distributed (parallelism N)"` when a Ballista cluster is configured
///
/// Registered per-session by the server (same `StartupObserver` seam as
/// [`current_database_udf`]) so any pgwire client — the testbench's
/// execution-mode badge is the motivating consumer — can ask the engine
/// itself rather than trusting a launch flag. Namespaced `dataglot_` to
/// avoid colliding with any Postgres or upstream function name. Marked
/// `Stable`: constant for the life of the server process.
#[must_use]
pub fn execution_mode_udf(mode: &str) -> ScalarUDF {
    let mode = mode.to_string();
    let func = move |_args: &[ColumnarValue]| {
        let mut builder = StringBuilder::new();
        builder.append_value(&mode);
        let array: ArrayRef = Arc::new(builder.finish());
        Ok(ColumnarValue::Array(array))
    };
    create_udf(
        "dataglot_execution_mode",
        vec![],
        DataType::Utf8,
        Volatility::Stable,
        Arc::new(func),
    )
}

/// Server version this engine advertises over the pg wire protocol.
///
/// These MUST stay in sync with what the pgwire layer reports in the
/// startup `ParameterStatus` and `SHOW server_version[_num]` (currently
/// `16.6` / `160006`). They live in a different crate
/// (`datafusion-postgres`/`dataglot-pgwire`) that `dataglot-core` cannot
/// depend on, so the values are mirrored here for [`current_setting_udf`];
/// [`tests::current_setting_reports_the_advertised_server_version`] pins
/// them so a version bump that forgets this copy fails loudly.
const ADVERTISED_SERVER_VERSION: &str = "16.6";
const ADVERTISED_SERVER_VERSION_NUM: &str = "160006";

/// The static, server-wide **capability GUCs** that Postgres client drivers
/// (Npgsql — the driver Power BI uses — JDBC, libpq tools) read on connect to
/// negotiate wire behaviour, as `(name, value)` pairs.
///
/// Single source of truth for both [`current_setting_udf`] (looked up by name,
/// case-insensitively) and the `pg_settings` overlay in
/// [`crate::pg_catalog_overlay`] (enumerated as table rows) — so the function
/// and the table can never disagree. Names use the canonical PostgreSQL
/// spelling (e.g. `DateStyle`); lookups are case-insensitive.
///
/// Scope is deliberately capability settings only. Session-mutable GUCs
/// (`search_path`, `application_name`, a live `TimeZone`, …) are **not**
/// faithfully per-session here — the values are the server defaults; true
/// per-session GUC state is a follow-up once identity / session config is
/// threaded into the catalog.
pub(crate) const CAPABILITY_GUCS: &[(&str, &str)] = &[
    ("server_version", ADVERTISED_SERVER_VERSION),
    ("server_version_num", ADVERTISED_SERVER_VERSION_NUM),
    ("standard_conforming_strings", "on"),
    ("client_encoding", "UTF8"),
    ("server_encoding", "UTF8"),
    ("integer_datetimes", "on"),
    ("max_index_keys", "32"),
    ("DateStyle", "ISO, MDY"),
    ("IntervalStyle", "postgres"),
    ("TimeZone", "UTC"),
    ("bytea_output", "hex"),
    ("lc_collate", "C"),
    ("lc_ctype", "C"),
    ("search_path", "\"$user\", public"),
];

/// Resolve a `pg_catalog` GUC to its value, or `None` if not modelled.
/// Case-insensitive, as Postgres treats GUC names.
fn lookup_guc(name: &str) -> Option<&'static str> {
    CAPABILITY_GUCS
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| *v)
}

/// `current_setting(name text) -> text` and
/// `current_setting(name text, missing_ok boolean) -> text`.
///
/// Postgres client drivers (Npgsql / .NET, which Power BI's PostgreSQL
/// connector uses; JDBC; libpq tools) call `current_setting('…')` on
/// connect to read capability GUCs — e.g.
/// `current_setting('server_version_num')`,
/// `current_setting('standard_conforming_strings')`. Neither DataFusion
/// nor `datafusion-pg-catalog` provides it, so those probes fail with
/// `Invalid function 'current_setting'`, degrading or breaking the
/// connection ( — Power BI client compat).
///
/// Semantics match Postgres: an unknown parameter errors, unless the
/// two-arg form is called with `missing_ok = true`, which returns `NULL`.
/// Values come from [`lookup_guc`] (static capability GUCs). Marked
/// `Stable`: constant within a session.
#[derive(Debug, PartialEq, Eq, Hash)]
struct CurrentSettingUdf {
    signature: Signature,
}

impl CurrentSettingUdf {
    fn new() -> Self {
        Self {
            signature: Signature::one_of(
                vec![
                    TypeSignature::Exact(vec![DataType::Utf8]),
                    TypeSignature::Exact(vec![DataType::Utf8, DataType::Boolean]),
                ],
                Volatility::Stable,
            ),
        }
    }
}

impl ScalarUDFImpl for CurrentSettingUdf {
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "current_setting"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DfResult<DataType> {
        Ok(DataType::Utf8)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DfResult<ColumnarValue> {
        let arrays = ColumnarValue::values_to_arrays(&args.args)?;
        let names = arrays[0]
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| {
                DataFusionError::Execution("current_setting: name must be text".to_string())
            })?;
        // Optional second arg: missing_ok. Absent ⇒ errors on unknown GUC.
        let missing_ok = arrays
            .get(1)
            .and_then(|a| a.as_any().downcast_ref::<BooleanArray>());

        let mut builder = StringBuilder::new();
        for i in 0..names.len() {
            if names.is_null(i) {
                builder.append_null();
                continue;
            }
            let name = names.value(i);
            if let Some(value) = lookup_guc(name) {
                builder.append_value(value);
            } else if missing_ok.is_some_and(|a| !a.is_null(i) && a.value(i)) {
                builder.append_null();
            } else {
                // Mirror Postgres' error text/shape for an unknown GUC.
                return Err(DataFusionError::Execution(format!(
                    "unrecognized configuration parameter \"{name}\""
                )));
            }
        }
        Ok(ColumnarValue::Array(Arc::new(builder.finish())))
    }
}

/// Build the `current_setting` scalar UDF for registration.
#[must_use]
pub fn current_setting_udf() -> ScalarUDF {
    ScalarUDF::from(CurrentSettingUdf::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::{Float64Array, Int64Array};
    use datafusion::prelude::SessionContext;

    #[tokio::test]
    async fn mod_integer() {
        let ctx = SessionContext::new();
        ctx.register_udf(mod_udf());
        let batches = ctx
            .sql("SELECT mod(7, 3) AS r")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        let col = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("Int64 result");
        assert_eq!(col.value(0), 1);
    }

    #[tokio::test]
    async fn mod_float() {
        let ctx = SessionContext::new();
        ctx.register_udf(mod_udf());
        let batches = ctx
            .sql("SELECT mod(7.5, 2.0) AS r")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        let col = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("Float64 result");
        assert!((col.value(0) - 1.5).abs() < 1e-9);
    }

    ///: modulo-by-zero. Integer `mod(x, 0)` must ERROR (Arrow's
    /// integer `rem` kernel returns `DivideByZero`, matching Postgres /
    /// Trino "division by zero" — the compat targets this shim exists
    /// for). Pinned so it can never silently regress to a panic or a
    /// wrong value.
    #[tokio::test]
    async fn mod_integer_by_zero_errors() {
        let ctx = SessionContext::new();
        ctx.register_udf(mod_udf());
        let result = ctx
            .sql("SELECT mod(5, 0) AS r")
            .await
            .unwrap()
            .collect()
            .await;
        assert!(
            result.is_err(),
            "integer mod by zero must error (Postgres parity), got {result:?}"
        );
    }

    ///: float `mod(x, 0.0)` currently returns IEEE `NaN` (Arrow's
    /// float `rem` kernel), which DIVERGES from Postgres (raises
    /// "division by zero"). NaN is a defensible IEEE result, so this
    /// pins the current behavior as a documented divergence rather than
    /// asserting a fix — flip to an error assertion if the team decides
    /// float mod should match Postgres.
    #[tokio::test]
    async fn mod_float_by_zero_is_nan_documented_divergence() {
        let ctx = SessionContext::new();
        ctx.register_udf(mod_udf());
        let batches = ctx
            .sql("SELECT mod(5.0, 0.0) AS r")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        let col = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("Float64 result");
        assert!(
            col.value(0).is_nan(),
            "float mod by zero currently yields NaN (documented Postgres divergence)"
        );
    }

    #[tokio::test]
    async fn current_database_returns_the_registered_name() {
        use datafusion::arrow::array::StringArray;
        let ctx = SessionContext::new();
        ctx.register_udf(current_database_udf("pg_orders"));
        let batches = ctx
            .sql("SELECT current_database() AS db")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        let col = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("Utf8 result");
        assert_eq!(col.value(0), "pg_orders");
    }

    ///  — `session_user()` (and `current_user`, rewritten to it) must
    /// report the connection's login role, not the upstream constant.
    #[tokio::test]
    async fn session_user_returns_the_connection_user() {
        use datafusion::arrow::array::StringArray;
        let ctx = SessionContext::new();
        ctx.register_udf(session_user_udf("analyst"));
        // `session_user` is a SQL keyword; DataFusion lowers it to a call of
        // the registered `session_user` function (over the wire the pg layer
        // does the same rewrite). No parens — `session_user()` is a parse error.
        let batches = ctx
            .sql("SELECT session_user AS u")
            .await
            .expect("plans")
            .collect()
            .await
            .expect("executes");
        let col = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("Utf8 result");
        assert_eq!(col.value(0), "analyst");
    }

    #[tokio::test]
    async fn execution_mode_returns_the_registered_mode() {
        use datafusion::arrow::array::StringArray;
        let ctx = SessionContext::new();
        ctx.register_udf(execution_mode_udf("distributed (parallelism 8)"));
        let batches = ctx
            .sql("SELECT dataglot_execution_mode() AS m")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        let col = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("Utf8 result");
        assert_eq!(col.value(0), "distributed (parallelism 8)");
    }

    ///  — psql v16+'s `\dt` calls `pg_table_is_visible(oid)`;
    /// the shim answers true for every row.
    #[tokio::test]
    async fn pg_table_is_visible_is_uniformly_true() {
        let ctx = SessionContext::new();
        ctx.register_udf(pg_table_is_visible_udf());
        let batches = ctx
            .sql("SELECT pg_table_is_visible(x) AS v FROM (VALUES (1), (2), (3)) t(x)")
            .await
            .expect("plans")
            .collect()
            .await
            .expect("executes");
        let col = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<datafusion::arrow::array::BooleanArray>()
            .expect("bool col");
        assert_eq!(col.len(), 3);
        assert!((0..3).all(|i| col.value(i)));
    }

    #[tokio::test]
    async fn df_dt_helper_shims_resolve_empty_or_null() {
        // psql \df / \dT / \d+ select these helpers; they must exist so the
        // meta-command query plans (else `Invalid function …`). Dataglot models
        // no user functions or object comments, so results are empty / NULL
        use datafusion::arrow::array::StringArray;
        let ctx = SessionContext::new();
        ctx.register_udf(pg_get_function_result_udf());
        ctx.register_udf(pg_get_function_arguments_udf());
        ctx.register_udf(obj_description_udf());
        ctx.register_udf(shobj_description_udf());
        ctx.register_udf(col_description_udf());
        let b = ctx
            .sql(
                "SELECT pg_get_function_result(1) AS r, \
                        pg_get_function_arguments(1) AS a, \
                        obj_description(1, 'pg_type') AS d, \
                        shobj_description(1, 'pg_authid') AS s, \
                        col_description(1, 1) AS c",
            )
            .await
            .expect("plans")
            .collect()
            .await
            .expect("executes");
        let s = |i: usize| {
            b[0].column(i)
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("str col")
        };
        assert_eq!(s(0).value(0), "", "pg_get_function_result is empty");
        assert_eq!(s(1).value(0), "", "pg_get_function_arguments is empty");
        assert!(s(2).is_null(0), "obj_description is NULL");
        assert!(s(3).is_null(0), "shobj_description is NULL");
        assert!(s(4).is_null(0), "col_description is NULL");

        // Row count must follow an ARRAY argument even when the first arg is a
        // scalar: `col_description(1, x)` over a 3-row column returns 3 NULLs.
        let b2 = ctx
            .sql("SELECT col_description(1, x) AS c FROM (VALUES (1),(2),(3)) t(x)")
            .await
            .expect("plans")
            .collect()
            .await
            .expect("executes");
        let c = b2[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("str col");
        assert_eq!(
            c.len(),
            3,
            "sized from the array arg, not the scalar first arg"
        );
        assert!((0..3).all(|i| c.is_null(i)), "all NULL");
    }

    #[tokio::test]
    async fn current_database_reregistration_overrides_by_name() {
        use datafusion::arrow::array::StringArray;
        // `register_udf` replaces by name — the last registration wins,
        // which is what lets the per-session override shadow the upstream
        // hardcoded `current_database()`.
        let ctx = SessionContext::new();
        ctx.register_udf(current_database_udf("first"));
        ctx.register_udf(current_database_udf("second"));
        let batches = ctx
            .sql("SELECT current_database() AS db")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        let col = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(col.value(0), "second");
    }

    ///  — Npgsql (Power BI's driver) reads capability GUCs via
    /// `current_setting('…')` on connect. Resolve a representative set.
    #[tokio::test]
    async fn current_setting_resolves_capability_gucs() {
        use datafusion::arrow::array::StringArray;
        let ctx = SessionContext::new();
        ctx.register_udf(current_setting_udf());
        let batches = ctx
            .sql(
                "SELECT current_setting('server_version_num') AS a, \
                        current_setting('standard_conforming_strings') AS b, \
                        current_setting('MAX_INDEX_KEYS') AS c",
            )
            .await
            .expect("plans")
            .collect()
            .await
            .expect("executes");
        let s = |col: usize| {
            batches[0]
                .column(col)
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("Utf8")
                .value(0)
                .to_string()
        };
        assert_eq!(s(0), "160006");
        assert_eq!(s(1), "on");
        assert_eq!(s(2), "32", "GUC names are case-insensitive");
    }

    /// The two-arg `missing_ok = true` form returns NULL for an unknown
    /// GUC instead of erroring (Postgres parity).
    #[tokio::test]
    async fn current_setting_missing_ok_returns_null() {
        use datafusion::arrow::array::{Array, StringArray};
        let ctx = SessionContext::new();
        ctx.register_udf(current_setting_udf());
        let batches = ctx
            .sql("SELECT current_setting('no.such.param', true) AS v")
            .await
            .expect("plans")
            .collect()
            .await
            .expect("executes");
        let col = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("Utf8");
        assert!(col.is_null(0), "missing_ok=true yields NULL");
    }

    /// The one-arg form errors on an unknown GUC (Postgres parity).
    #[tokio::test]
    async fn current_setting_unknown_errors() {
        let ctx = SessionContext::new();
        ctx.register_udf(current_setting_udf());
        let result = ctx
            .sql("SELECT current_setting('no.such.param') AS v")
            .await
            .expect("plans")
            .collect()
            .await;
        assert!(result.is_err(), "unknown GUC without missing_ok must error");
    }

    /// Pins the advertised server version copied into `dataglot-core` so a
    /// pgwire-layer version bump that forgets this mirror fails loudly.
    #[test]
    fn current_setting_reports_the_advertised_server_version() {
        assert_eq!(
            lookup_guc("server_version"),
            Some(ADVERTISED_SERVER_VERSION)
        );
        assert_eq!(
            lookup_guc("server_version_num"),
            Some(ADVERTISED_SERVER_VERSION_NUM)
        );
        assert_eq!(ADVERTISED_SERVER_VERSION, "16.6");
        assert_eq!(ADVERTISED_SERVER_VERSION_NUM, "160006");
    }

    #[tokio::test]
    async fn mod_is_case_insensitive() {
        let ctx = SessionContext::new();
        ctx.register_udf(mod_udf());
        // DataFusion lowercases function names, so MOD resolves too.
        let batches = ctx
            .sql("SELECT MOD(10, 4) AS r")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        let col = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();
        assert_eq!(col.value(0), 2);
    }
}
