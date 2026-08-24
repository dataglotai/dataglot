//! Server-side implementation of the pgwire [`PolicyAdmin`] seam — the
//! effecting half of `CREATE / DROP MASK` and `CREATE / DROP ROW FILTER`
//!
//! [`dataglot_pgwire::policy_ddl`] parses the statement; [`StorePolicyAdmin`]
//! here does two things per statement, in order:
//!
//! 1. **Enforce.** Turn the `PolicyDdl` into the *same* `MaskConfig` /
//!    `RowFilterConfig` the config `[[masks]]` / `[[row_filters]]` blocks use,
//!    lower it into a native `ColumnMask` / `RowFilter` via the existing
//!    config→enforcer path (`config::build_mask_rules` /
//!    `config::build_row_filter_rules`), and apply it to the live
//!    [`InMemoryRuleStore`] as a [`RuleChange`] — the same mutation seam the
//!    inbound governance webhook uses. The published `MutableEnforcer` swaps,
//!    so every active session masks/filters on its next query (rule 6: the
//!    mechanism stays a plan-time `Expr` `OptimizerRule`; only the rule's
//!    *declaration source* is new). If the enforcer rejects the rule the
//!    statement fails and **nothing is persisted**.
//! 2. **Persist.** Store the serialized `MaskConfig` / `RowFilterConfig` under
//!    the connection's org via [`MetaStore::put_policy`] (opaque JSON — rule 4:
//!    the store never interprets it), so the rule survives restart (the boot
//!    path replays it — see [`crate::server`]'s `load_persisted_policies`).
//!
//! `DROP` inverts both: remove the rule from the enforcer (the inverse
//! `RuleChange`) and [`MetaStore::delete_policy`].
//!
//! # Per-org enforcement
//!
//! Both persistence *and* enforcement are org-scoped. Persistence keys on the
//! connection's org (each `apply` call carries it). Enforcement is per-tenant
//! too: the live rule is tagged with the issuing session's org
//! (`ColumnMask.org` / `RowFilter.org = Some(org)`), so the one process-global
//! [`InMemoryRuleStore`] / `MutableEnforcer` can hold every tenant's rules at
//! once and each session's `rewrite` only fires the rules whose org is `None`
//! (operator-wide, i.e. file-config) or matches its own. A `CREATE MASK` under
//! `acme` therefore masks only `acme` sessions, and `DROP` scopes its
//! `RuleChange::MaskRemoved` / `RowFilterRemoved` to the same org so it can't
//! evict another tenant's rule on the same resource.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use dataglot_catalog::MetaStore;
use dataglot_pgwire::policy_admin::{PolicyAdmin, PolicyAdminError, PolicyOutcome};
use dataglot_pgwire::policy_ddl::{PolicyDdl, PolicyMask};
use dataglot_policy::{InMemoryRuleStore, RuleChange, RuleStore};

use crate::config::{
    build_mask_rules, build_row_filter_rules, parse_table_ref, MaskConfig, MaskTypeConfig,
    RowFilterConfig, RowPredicateConfig,
};

/// Policy kinds as persisted in the meta store (matching
/// `dataglot_catalog::PolicyRecord::kind`).
const KIND_MASK: &str = "mask";
const KIND_ROW_FILTER: &str = "row_filter";

/// [`PolicyAdmin`] backed by the [`MetaStore`] (org-scoped persistence) and the
/// process-global [`InMemoryRuleStore`] (live enforcement). See the module docs
/// for the enforce-then-persist ordering and the single-tenant-enforcement
/// caveat.
///
///  M2: one admin serves every org — the target org arrives per
/// [`PolicyAdmin::apply`] call (threaded from the connection's session identity
/// by the pgwire handler).
#[derive(Clone)]
pub struct StorePolicyAdmin {
    store: Arc<dyn MetaStore>,
    rule_store: Arc<InMemoryRuleStore>,
}

impl StorePolicyAdmin {
    /// Wrap a control-plane store + the live rule store. The target org is
    /// supplied per [`PolicyAdmin::apply`] call.
    #[must_use]
    pub fn new(store: Arc<dyn MetaStore>, rule_store: Arc<InMemoryRuleStore>) -> Self {
        Self { store, rule_store }
    }
}

/// Map a store error into a client-safe [`PolicyAdminError::Backend`].
fn backend(e: &dataglot_catalog::CatalogServiceError) -> PolicyAdminError {
    PolicyAdminError::Backend(format!("policy store: {e}"))
}

/// Assemble a [`MaskTypeConfig`] from the parsed `WITH ( type = … )` option bag
/// ( M4b — the "M4b to assemble" note in `policy_ddl`). Unknown types or
/// missing/invalid params are a client mistake surfaced as a clear, value-free
/// message.
fn mask_type_from_options(
    mask_type: &str,
    options: &HashMap<String, String>,
) -> Result<MaskTypeConfig, PolicyAdminError> {
    let keep = || -> Result<usize, PolicyAdminError> {
        options
            .get("keep")
            .ok_or_else(|| {
                PolicyAdminError::Backend(format!(
                    "mask type {mask_type:?} requires a `keep` option"
                ))
            })?
            .parse::<usize>()
            .map_err(|_| {
                PolicyAdminError::Backend(format!(
                    "mask type {mask_type:?}: `keep` must be a non-negative integer"
                ))
            })
    };
    Ok(match mask_type.to_ascii_lowercase().as_str() {
        "redact" => MaskTypeConfig::Redact,
        "hash" => MaskTypeConfig::Hash,
        "nullify" => MaskTypeConfig::Nullify,
        "date_year" => MaskTypeConfig::DateYear,
        "show_last" => MaskTypeConfig::ShowLast { keep: keep()? },
        "show_first" => MaskTypeConfig::ShowFirst { keep: keep()? },
        "constant" => MaskTypeConfig::Constant {
            value: options
                .get("value")
                .ok_or_else(|| {
                    PolicyAdminError::Backend(
                        "mask type \"constant\" requires a `value` option".to_string(),
                    )
                })?
                .clone(),
        },
        other => {
            return Err(PolicyAdminError::Backend(format!(
                "unknown mask type {other:?} (expected redact / show_last / show_first / \
                 hash / nullify / date_year / constant)"
            )))
        }
    })
}

/// Build the [`MaskConfig`] a `CREATE MASK` declares.
fn mask_config(
    table: String,
    column: String,
    mask: PolicyMask,
) -> Result<MaskConfig, PolicyAdminError> {
    let (mask_literal, mask_type) = match mask {
        PolicyMask::Literal(literal) => (literal, None),
        PolicyMask::Typed { mask_type, options } => (
            String::new(),
            Some(mask_type_from_options(&mask_type, &options)?),
        ),
    };
    Ok(MaskConfig {
        table,
        column,
        mask_literal,
        mask_type,
        mask_expr: None,
        priority: 0,
        // `CREATE MASK` has no `FOR ROLE` syntax yet ( config path only);
        // a DDL-created mask applies to all subjects in the org.
        groups: None,
    })
}

/// Serialize a config value into the opaque JSON the store persists.
fn to_value<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, PolicyAdminError> {
    serde_json::to_value(value)
        .map_err(|e| PolicyAdminError::Backend(format!("serialize policy: {e}")))
}

impl StorePolicyAdmin {
    /// Apply a `RuleChange` to the live enforcer, mapping a rejection to a
    /// value-free [`PolicyAdminError::Backend`] (the statement fails; the caller
    /// must not persist).
    fn enforce(&self, change: RuleChange) -> Result<(), PolicyAdminError> {
        self.rule_store
            .apply(change)
            .map_err(|e| PolicyAdminError::Backend(format!("policy enforcement rejected: {e}")))
    }

    /// `true` if a policy of any kind already exists under `(org, name)`.
    async fn name_taken(&self, org: &str, name: &str) -> Result<bool, PolicyAdminError> {
        Ok(self
            .store
            .get_policy(org, name)
            .await
            .map_err(|e| backend(&e))?
            .is_some())
    }

    /// `CREATE MASK`: enforce then persist. See the module docs for ordering.
    async fn create_mask(
        &self,
        org: &str,
        name: String,
        table: String,
        column: String,
        mask: PolicyMask,
        if_not_exists: bool,
    ) -> Result<PolicyOutcome, PolicyAdminError> {
        if self.name_taken(org, &name).await? {
            return if if_not_exists {
                Ok(PolicyOutcome::NoOp)
            } else {
                Err(PolicyAdminError::AlreadyExists(name))
            };
        }
        let cfg = mask_config(table, column, mask)?;
        // Lower via the exact config→enforcer path.
        let mut column_mask = build_mask_rules(std::slice::from_ref(&cfg))
            .map_err(|e| PolicyAdminError::Backend(format!("invalid mask: {e}")))?
            .into_iter()
            .next()
            .ok_or_else(|| PolicyAdminError::Backend("mask produced no rule".to_string()))?;
        // Tag the live rule with the issuing session's org: a
        // runtime `CREATE MASK` is tenant-scoped, so it enforces only for
        // sessions in this org. `build_mask_rules` returns an operator-wide
        // (`org: None`) rule — the config default — which we override here.
        column_mask.org = Some(org.to_string());
        // Enforce first; only persist a rule the enforcer accepted.
        self.enforce(RuleChange::MaskUpserted(column_mask))?;
        self.store
            .put_policy(org, &name, KIND_MASK, &to_value(&cfg)?)
            .await
            .map_err(|e| backend(&e))?;
        Ok(PolicyOutcome::Created { name })
    }

    /// `CREATE ROW FILTER`: enforce then persist.
    async fn create_row_filter(
        &self,
        org: &str,
        name: String,
        table: String,
        predicate: String,
        if_not_exists: bool,
    ) -> Result<PolicyOutcome, PolicyAdminError> {
        if self.name_taken(org, &name).await? {
            return if if_not_exists {
                Ok(PolicyOutcome::NoOp)
            } else {
                Err(PolicyAdminError::AlreadyExists(name))
            };
        }
        let cfg = RowFilterConfig {
            table,
            predicate: RowPredicateConfig::Sql { sql: predicate },
            // `CREATE ROW FILTER` has no `FOR ROLE` syntax yet ( config
            // path only); a DDL-created filter applies to all subjects in the org.
            groups: None,
        };
        let mut row_filter = build_row_filter_rules(std::slice::from_ref(&cfg))
            .map_err(|e| PolicyAdminError::Backend(format!("invalid row filter: {e}")))?
            .into_iter()
            .next()
            .ok_or_else(|| PolicyAdminError::Backend("row filter produced no rule".to_string()))?;
        // Tenant-scope the live rule to the issuing session's org (
        // F4), overriding the operator-wide default `build_row_filter_rules`
        // returns.
        row_filter.org = Some(org.to_string());
        self.enforce(RuleChange::RowFilterUpserted(row_filter))?;
        self.store
            .put_policy(org, &name, KIND_ROW_FILTER, &to_value(&cfg)?)
            .await
            .map_err(|e| backend(&e))?;
        Ok(PolicyOutcome::Created { name })
    }

    /// `DROP MASK`: remove from the enforcer then the store.
    async fn drop_mask(
        &self,
        org: &str,
        name: String,
        if_exists: bool,
    ) -> Result<PolicyOutcome, PolicyAdminError> {
        let Some(value) = self.get_of_kind(org, &name, KIND_MASK).await? else {
            return if if_exists {
                Ok(PolicyOutcome::NoOp)
            } else {
                Err(PolicyAdminError::NotFound(name))
            };
        };
        let cfg: MaskConfig = serde_json::from_value(value)
            .map_err(|e| PolicyAdminError::Backend(format!("stored mask is corrupt: {e}")))?;
        let table = parse_table_ref(&cfg.table)
            .map_err(|e| PolicyAdminError::Backend(format!("stored mask table: {e}")))?;
        // Scope the removal to this org's rule — a `DROP MASK`
        // under org `acme` must not evict another tenant's mask on the same
        // (table, column). Matches the org this session's `CREATE MASK`
        // tagged the live rule with.
        self.enforce(RuleChange::MaskRemoved {
            table,
            column: cfg.column,
            org: Some(org.to_string()),
        })?;
        self.store
            .delete_policy(org, &name)
            .await
            .map_err(|e| backend(&e))?;
        Ok(PolicyOutcome::Dropped { name })
    }

    /// `DROP ROW FILTER`: remove from the enforcer then the store.
    async fn drop_row_filter(
        &self,
        org: &str,
        name: String,
        if_exists: bool,
    ) -> Result<PolicyOutcome, PolicyAdminError> {
        let Some(value) = self.get_of_kind(org, &name, KIND_ROW_FILTER).await? else {
            return if if_exists {
                Ok(PolicyOutcome::NoOp)
            } else {
                Err(PolicyAdminError::NotFound(name))
            };
        };
        let cfg: RowFilterConfig = serde_json::from_value(value)
            .map_err(|e| PolicyAdminError::Backend(format!("stored row filter is corrupt: {e}")))?;
        let table = parse_table_ref(&cfg.table)
            .map_err(|e| PolicyAdminError::Backend(format!("stored row-filter table: {e}")))?;
        // Scope the removal to this org's rule.
        self.enforce(RuleChange::RowFilterRemoved {
            table,
            org: Some(org.to_string()),
        })?;
        self.store
            .delete_policy(org, &name)
            .await
            .map_err(|e| backend(&e))?;
        Ok(PolicyOutcome::Dropped { name })
    }

    /// Fetch a persisted policy of the expected `kind`. Returns `Ok(None)` when
    /// there is no policy of that name/kind (a different-kind policy of the same
    /// name counts as absent for this statement's object type).
    async fn get_of_kind(
        &self,
        org: &str,
        name: &str,
        kind: &str,
    ) -> Result<Option<serde_json::Value>, PolicyAdminError> {
        match self
            .store
            .get_policy(org, name)
            .await
            .map_err(|e| backend(&e))?
        {
            Some((k, value)) if k == kind => Ok(Some(value)),
            _ => Ok(None),
        }
    }
}

#[async_trait]
impl PolicyAdmin for StorePolicyAdmin {
    async fn apply(&self, org: &str, ddl: PolicyDdl) -> Result<PolicyOutcome, PolicyAdminError> {
        match ddl {
            PolicyDdl::CreateMask {
                name,
                table,
                column,
                mask,
                if_not_exists,
            } => {
                self.create_mask(org, name, table, column, mask, if_not_exists)
                    .await
            }
            PolicyDdl::CreateRowFilter {
                name,
                table,
                predicate,
                if_not_exists,
            } => {
                self.create_row_filter(org, name, table, predicate, if_not_exists)
                    .await
            }
            PolicyDdl::DropMask { name, if_exists } => self.drop_mask(org, name, if_exists).await,
            PolicyDdl::DropRowFilter { name, if_exists } => {
                self.drop_row_filter(org, name, if_exists).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use datafusion::arrow::array::StringArray;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;
    use datafusion::prelude::SessionContext;
    use dataglot_catalog::embedded::EmbeddedMetaStore;
    use dataglot_policy::{Identity, InitialRules};

    use super::*;

    async fn setup() -> (
        Arc<dyn MetaStore>,
        Arc<InMemoryRuleStore>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store: Arc<dyn MetaStore> = Arc::new(
            EmbeddedMetaStore::open(dir.path().join("m.json"), "default")
                .await
                .expect("store"),
        );
        let rule_store = InMemoryRuleStore::new(InitialRules::default()).expect("rule store");
        (store, rule_store, dir)
    }

    /// Run `SELECT email FROM users` through the rule store's current
    /// enforcer under `identity`, returning the (possibly masked) value.
    /// The identity matters now that runtime masks are tenant-scoped
    /// — pass an `acme` session to observe an `acme`-created
    /// mask.
    async fn masked_email_as(rule_store: &InMemoryRuleStore, identity: &Identity) -> String {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            DataType::Utf8,
            false,
        )]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(StringArray::from(vec!["real@example.com"]))],
        )
        .unwrap();
        let ctx = SessionContext::new();
        ctx.register_table(
            "users",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();
        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .unwrap()
            .logical_plan()
            .clone();
        let rewritten = rule_store
            .snapshot()
            .rewrite(plan, identity)
            .expect("rewrite")
            .data;
        let batches = ctx
            .execute_logical_plan(rewritten)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap()
            .value(0)
            .to_string()
    }

    fn create_mask(name: &str) -> PolicyDdl {
        PolicyDdl::CreateMask {
            name: name.to_string(),
            table: "users".to_string(),
            column: "email".to_string(),
            mask: PolicyMask::Literal("***@example.com".to_string()),
            if_not_exists: false,
        }
    }

    #[tokio::test]
    async fn create_mask_persists_under_org_and_enforces() {
        let (store, rule_store, _d) = setup().await;
        let admin = StorePolicyAdmin::new(Arc::clone(&store), Arc::clone(&rule_store));

        let acme = Identity::user("a").with_org("acme");

        // Before: raw.
        assert_eq!(
            masked_email_as(&rule_store, &acme).await,
            "real@example.com"
        );

        admin
            .apply("acme", create_mask("email_mask"))
            .await
            .expect("create");

        // Persisted under the passed org, invisible to another org.
        assert!(store
            .get_policy("acme", "email_mask")
            .await
            .unwrap()
            .is_some());
        assert!(store
            .get_policy("default", "email_mask")
            .await
            .unwrap()
            .is_none());
        // The enforcer masks for an acme session (the org that created it)...
        assert_eq!(masked_email_as(&rule_store, &acme).await, "***@example.com");
        // ...but NOT for another tenant, nor for an anonymous session — the
        // runtime mask is tenant-scoped.
        assert_eq!(
            masked_email_as(&rule_store, &Identity::user("b").with_org("beta")).await,
            "real@example.com",
            "an acme-created mask must not mask a beta session"
        );
        assert_eq!(
            masked_email_as(&rule_store, &Identity::anonymous()).await,
            "real@example.com",
            "an acme-created mask must not mask an anonymous session"
        );
    }

    #[tokio::test]
    async fn drop_mask_removes_from_store_and_enforcer() {
        let (store, rule_store, _d) = setup().await;
        let admin = StorePolicyAdmin::new(Arc::clone(&store), Arc::clone(&rule_store));
        let acme = Identity::user("a").with_org("acme");
        admin
            .apply("acme", create_mask("email_mask"))
            .await
            .expect("create");
        assert_eq!(masked_email_as(&rule_store, &acme).await, "***@example.com");

        let out = admin
            .apply(
                "acme",
                PolicyDdl::DropMask {
                    name: "email_mask".to_string(),
                    if_exists: false,
                },
            )
            .await
            .expect("drop");
        assert!(matches!(out, PolicyOutcome::Dropped { .. }));
        assert!(store
            .get_policy("acme", "email_mask")
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            masked_email_as(&rule_store, &acme).await,
            "real@example.com"
        );
    }

    #[tokio::test]
    async fn create_duplicate_and_if_not_exists() {
        let (store, rule_store, _d) = setup().await;
        let admin = StorePolicyAdmin::new(store, rule_store);
        admin.apply("acme", create_mask("m")).await.expect("first");

        let err = admin
            .apply("acme", create_mask("m"))
            .await
            .expect_err("dup");
        assert!(matches!(err, PolicyAdminError::AlreadyExists(ref n) if n == "m"));

        let ine = PolicyDdl::CreateMask {
            name: "m".to_string(),
            table: "users".to_string(),
            column: "email".to_string(),
            mask: PolicyMask::Literal("x".to_string()),
            if_not_exists: true,
        };
        assert!(matches!(
            admin.apply("acme", ine).await.unwrap(),
            PolicyOutcome::NoOp
        ));
    }

    #[tokio::test]
    async fn drop_missing_reports_existence() {
        let (store, rule_store, _d) = setup().await;
        let admin = StorePolicyAdmin::new(store, rule_store);
        // Without IF EXISTS → NotFound.
        assert!(matches!(
            admin
                .apply(
                    "acme",
                    PolicyDdl::DropMask {
                        name: "ghost".to_string(),
                        if_exists: false
                    }
                )
                .await,
            Err(PolicyAdminError::NotFound(_))
        ));
        // With IF EXISTS → NoOp.
        assert!(matches!(
            admin
                .apply(
                    "acme",
                    PolicyDdl::DropMask {
                        name: "ghost".to_string(),
                        if_exists: true
                    }
                )
                .await
                .unwrap(),
            PolicyOutcome::NoOp
        ));
    }

    #[tokio::test]
    async fn row_filter_create_and_drop_round_trip() {
        let (store, rule_store, _d) = setup().await;
        let admin = StorePolicyAdmin::new(Arc::clone(&store), rule_store);
        admin
            .apply(
                "acme",
                PolicyDdl::CreateRowFilter {
                    name: "tenant".to_string(),
                    table: "orders".to_string(),
                    predicate: "tenant_id = 'acme'".to_string(),
                    if_not_exists: false,
                },
            )
            .await
            .expect("create");
        let (kind, _) = store.get_policy("acme", "tenant").await.unwrap().unwrap();
        assert_eq!(kind, "row_filter");

        admin
            .apply(
                "acme",
                PolicyDdl::DropRowFilter {
                    name: "tenant".to_string(),
                    if_exists: false,
                },
            )
            .await
            .expect("drop");
        assert!(store.get_policy("acme", "tenant").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn typed_mask_assembles_show_last() {
        let (store, rule_store, _d) = setup().await;
        let admin = StorePolicyAdmin::new(Arc::clone(&store), rule_store);
        let mut options = HashMap::new();
        options.insert("keep".to_string(), "4".to_string());
        admin
            .apply(
                "acme",
                PolicyDdl::CreateMask {
                    name: "partial".to_string(),
                    table: "users".to_string(),
                    column: "email".to_string(),
                    mask: PolicyMask::Typed {
                        mask_type: "show_last".to_string(),
                        options,
                    },
                    if_not_exists: false,
                },
            )
            .await
            .expect("typed create");
        // Persisted with a mask_type (not a literal).
        let (_kind, value) = store.get_policy("acme", "partial").await.unwrap().unwrap();
        let cfg: MaskConfig = serde_json::from_value(value).unwrap();
        assert!(cfg.mask_type.is_some());
    }

    #[tokio::test]
    async fn typed_mask_unknown_type_is_rejected_and_not_persisted() {
        let (store, rule_store, _d) = setup().await;
        let admin = StorePolicyAdmin::new(Arc::clone(&store), rule_store);
        let err = admin
            .apply(
                "acme",
                PolicyDdl::CreateMask {
                    name: "bad".to_string(),
                    table: "users".to_string(),
                    column: "email".to_string(),
                    mask: PolicyMask::Typed {
                        mask_type: "nonsense".to_string(),
                        options: HashMap::new(),
                    },
                    if_not_exists: false,
                },
            )
            .await
            .expect_err("unknown type");
        assert!(matches!(err, PolicyAdminError::Backend(_)));
        // Nothing persisted (the assembly failed before any store write).
        assert!(store.get_policy("acme", "bad").await.unwrap().is_none());
    }
}
