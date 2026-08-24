//! Mutable rule registry — Phase 2 spec 04 slice 2.
//!
//! `InMemoryRuleStore` owns the live rule set, accepts atomic
//! mutations via [`RuleStore::apply`], and publishes a freshly-rebuilt
//! enforcer through its internal [`MutableEnforcer`] handle so every
//! active session picks up the change on the next query. The hot
//! read path (query optimizer) goes through [`MutableEnforcer`]; the
//! store's `RwLock` is only acquired on the rule-mutation path.
//!
//! # Source of truth
//!
//! The store is canonical. The published `Arc<dyn PolicyEnforcer>`
//! is a *cache* — recomputed-on-write — and never modified directly.
//! That keeps the publication boundary identical to a fresh boot:
//! `apply()` rebuilds the entire enforcer from the current storage
//! and atomically swaps it in. Rule churn is rare (per tag event,
//! minutes-scale); rebuild cost is dwarfed by network I/O.
//!
//! # `RuleChange` variants
//!
//! The first six are 1:1 with Interface 3 `event_type` (the inbound
//! governance webhook):
//!
//! - [`RuleChange::TagAssigned`] / [`RuleChange::TagRemoved`] —
//!   adds/removes a tag id on a `(table, column)`.
//! - [`RuleChange::PolicyUpserted`] — upsert by `Policy::id` (existing
//!   policy with the same id is replaced).
//! - [`RuleChange::PolicyDeleted`] — delete by `policy_id`.
//! - [`RuleChange::CertificationUpserted`] / `CertificationDeleted` —
//!   slice 2 stores the certification in a sidecar map. Slice 3+
//!   surfaces it through Interface 5's column-definition sync; the
//!   enforcement-side semantics are deferred (certifications today
//!   never gate query results).
//!
//! The remaining four are the runtime SQL-native policy-DDL path
//!, mutating the same static mask / row-filter layers the
//! config `[[masks]]` / `[[row_filters]]` blocks seed at boot:
//!
//! - [`RuleChange::MaskUpserted`] / [`RuleChange::MaskRemoved`] —
//!   `CREATE / DROP MASK`; upsert/remove a static column mask by
//!   `(table, column)`.
//! - [`RuleChange::RowFilterUpserted`] / [`RuleChange::RowFilterRemoved`]
//!   — `CREATE / DROP ROW FILTER`; upsert/remove a static row filter by
//!   `table`.
//!
//! # Slice 2 scope
//!
//! - The `RuleStore` trait, `InMemoryRuleStore` impl, `RuleChange`
//!   enum, and the rebuild-and-swap mechanics.
//! - Unit tests covering each variant's effect on a subsequent
//!   `snapshot().rewrite(plan)` call.
//! - Concurrent read-during-swap stress test (in `mutable.rs`).
//!
//! Out of scope for slice 2: the webhook → store dispatcher (slice
//! 3), and the persistence-to-catalog upgrade (deferred entirely;
//! see spec 04 §"Out of scope").

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use datafusion::sql::TableReference;
use thiserror::Error;

use crate::filter::BuildError as RowFilterBuildError;
use crate::mask::BuildError as ColumnMaskBuildError;
use crate::{
    ColumnMask, ColumnMaskingEnforcer, CompositeEnforcer, MutableEnforcer, NoopPolicyEnforcer,
    OrgGovernance, OrgGovernanceBuildError, Policy, PolicyEnforcer, RowFilter, RowFilterEnforcer,
    SemanticTableColumn, TagBasedEnforcer, TagDefinition, TagId,
};

/// Atomic mutation applied to the live rule set. The first six
/// variants are one-per Interface 3 `event_type` (the inbound
/// governance webhook path). The trailing four
/// (`MaskUpserted` / `MaskRemoved` / `RowFilterUpserted` /
/// `RowFilterRemoved`) are the runtime SQL-native policy-DDL path
///: `CREATE / DROP MASK` and `CREATE / DROP ROW FILTER`
/// mutate the same static mask / row-filter layers the config
/// `[[masks]]` / `[[row_filters]]` blocks seed at boot, so a
/// runtime-declared rule enforces exactly like a configured one.
/// See the module docs for the carried payload and the per-variant
/// effect on enforcement.
#[derive(Debug, Clone)]
pub enum RuleChange {
    /// Bind a tag to a `(table, column)`. Idempotent: re-asserting an
    /// existing binding is a no-op (no error, no enforcer rebuild).
    TagAssigned {
        /// Target table the column lives in.
        table: TableReference,
        /// Column name within `table`.
        column: String,
        /// Tag to bind.
        tag: TagId,
    },
    /// Remove a tag binding. Idempotent: removing an absent binding
    /// is a no-op (no error). Other tags on the same column survive.
    TagRemoved {
        /// Target table.
        table: TableReference,
        /// Column name.
        column: String,
        /// Tag to unbind.
        tag: TagId,
    },
    /// Upsert a policy by `Policy::id`. If a policy with the same id
    /// already exists, it is replaced atomically.
    PolicyUpserted(Policy),
    /// Delete a policy by id. No-op if the id is absent.
    PolicyDeleted {
        /// Stable id matching `Policy::id`.
        policy_id: String,
    },
    /// Record a steward certification on a `(table, column)`. Slice
    /// 2 stores this in a sidecar map; the on-query enforcement path
    /// does not gate on certifications. Slice 3+ surfaces it via
    /// Interface 5's column-definition sync.
    CertificationUpserted {
        /// Target table.
        table: TableReference,
        /// Column name.
        column: String,
        /// Free-form certification identifier (steward name, level,
        /// etc.). Opaque to the enforcement path.
        certification: String,
    },
    /// Remove a steward certification.
    CertificationDeleted {
        /// Target table.
        table: TableReference,
        /// Column name.
        column: String,
        /// Certification identifier to remove. Other certifications
        /// on the same column survive.
        certification: String,
    },
    /// Upsert a static, unconditional column mask by `(table, column, org)`
    /// — the runtime-DDL (`CREATE MASK`) analogue of a config
    /// `[[masks]]` entry. Replaces any existing mask on the same
    /// `(table, column, org)` (the [`ColumnMaskingEnforcer`] keeps one rule
    /// per key *per org* since  F4 — a re-upsert under org `acme`
    /// replaces `acme`'s mask on that `(table, column)` and leaves another
    /// tenant's mask on the same key untouched). A byte-identical re-upsert
    /// is an idempotent no-op.
    MaskUpserted(ColumnMask),
    /// Remove a static column mask by `(table, column, org)`. Idempotent:
    /// removing an absent mask is a no-op (no error). The `org` scopes the
    /// removal to the tenant that owns the rule — a `DROP MASK`
    /// under org `acme` must not remove another tenant's mask on the same
    /// `(table, column)`. `None` targets the operator-wide (config) rule.
    MaskRemoved {
        /// Target table the masked column lives in.
        table: TableReference,
        /// Masked column name within `table`.
        column: String,
        /// Owning org of the rule to remove (`None` = operator-wide).
        org: Option<String>,
    },
    /// Upsert a static, unconditional row filter by `(table, org)` — the
    /// runtime-DDL (`CREATE ROW FILTER`) analogue of a config
    /// `[[row_filters]]` entry. Replaces any existing filter on the
    /// same `(table, org)` (the [`RowFilterEnforcer`] keeps one rule per
    /// table *per org* since  F4 — a re-upsert under org `acme`
    /// replaces `acme`'s filter on that `table` and leaves another tenant's
    /// filter on the same `table` untouched). A byte-identical re-upsert is
    /// an idempotent no-op.
    RowFilterUpserted(RowFilter),
    /// Remove a static row filter by `(table, org)`. Idempotent: removing
    /// an absent filter is a no-op (no error). The `org` scopes the removal
    /// to the tenant that owns the rule — a `DROP ROW FILTER`
    /// under org `acme` must not remove another tenant's filter on the same
    /// `table`. `None` targets the operator-wide (config) rule.
    RowFilterRemoved {
        /// Target table whose row filter is removed.
        table: TableReference,
        /// Owning org of the rule to remove (`None` = operator-wide).
        org: Option<String>,
    },
}

/// Errors surfaced by [`RuleStore::apply`] and the underlying
/// rebuild path. Every variant maps to an `OrgGovernance` / mask /
/// filter build error from `dataglot-policy::tags`, `mask`, or
/// `filter` — slice 2 doesn't introduce new failure modes, it
/// surfaces the existing ones at apply time instead of boot time.
#[derive(Debug, Error)]
pub enum ApplyError {
    /// Rebuilding the `OrgGovernance` failed (duplicate tag id,
    /// policy referencing unknown tag, column referencing unknown
    /// tag).
    #[error(transparent)]
    BuildGovernance(#[from] OrgGovernanceBuildError),
    /// Rebuilding the mask layer failed.
    #[error(transparent)]
    BuildMask(#[from] ColumnMaskBuildError),
    /// Rebuilding the row-filter layer failed.
    #[error(transparent)]
    BuildFilter(#[from] RowFilterBuildError),
}

/// Internal storage. The compose path rebuilds an enforcer from
/// this snapshot. Held under an `RwLock` so concurrent webhook
/// requests serialise on writes but reads (driven by
/// [`MutableEnforcer`]) never block on it.
#[derive(Debug, Default)]
struct RuleStorage {
    /// Static column-mask rules — the same shape
    /// [`ColumnMaskingEnforcer`] consumes.
    masks: Vec<ColumnMask>,
    /// Static row-filter rules — the same shape
    /// [`RowFilterEnforcer`] consumes.
    filters: Vec<RowFilter>,
    /// Tag definitions.
    tags: Vec<TagDefinition>,
    /// Policies keyed by `Policy::id` so upsert/delete are O(1).
    policies: HashMap<String, Policy>,
    /// Tag bindings keyed by `(table, column)`. Maintains uniqueness
    /// within a column's tag list — idempotent assignment.
    columns: HashMap<(TableReference, String), Vec<TagId>>,
    /// Sidecar certifications. Not yet consumed by the enforcement
    /// path; slice 3+ wires them through Interface 5.
    certifications: HashMap<(TableReference, String), Vec<String>>,
    /// Session default `(catalog, schema)` applied to the composed
    /// [`ColumnMaskingEnforcer`] for upgrade-matching.
    session_defaults: Option<(String, String)>,
}

impl RuleStorage {
    /// Rebuild the enforcer from the current storage snapshot.
    /// Mirrors `dataglot-server::config::build_policy_enforcer` but
    /// takes the policy-native primitives directly (no config-shape
    /// translation), so it's safe to run on every `apply()`.
    fn compose(&self) -> Result<Arc<dyn PolicyEnforcer>, ApplyError> {
        let mut layers: Vec<Arc<dyn PolicyEnforcer>> = Vec::with_capacity(3);

        // Tag-based layer. Skip when entirely empty so an empty
        // governance section doesn't show up as a no-op layer in
        // EXPLAIN.
        let has_tag_data =
            !self.tags.is_empty() || !self.policies.is_empty() || !self.columns.is_empty();
        if has_tag_data {
            let mut builder = OrgGovernance::builder();
            for t in &self.tags {
                builder = builder.with_tag(t.clone());
            }
            for p in self.policies.values() {
                builder = builder.with_policy(p.clone());
            }
            for ((table, column), tags) in &self.columns {
                if !tags.is_empty() {
                    builder = builder.with_column(SemanticTableColumn {
                        table: table.clone(),
                        column: column.clone(),
                        tags: tags.clone(),
                    });
                }
            }
            let governance = builder.build()?;
            layers.push(Arc::new(TagBasedEnforcer::new(governance)));
        }

        if !self.masks.is_empty() {
            let mut enforcer = ColumnMaskingEnforcer::new(self.masks.clone())?;
            if let Some((catalog, schema)) = &self.session_defaults {
                enforcer = enforcer.with_session_defaults(catalog.clone(), schema.clone());
            }
            layers.push(Arc::new(enforcer));
        }
        if !self.filters.is_empty() {
            layers.push(Arc::new(RowFilterEnforcer::new(self.filters.clone())?));
        }

        Ok(match layers.len() {
            0 => Arc::new(NoopPolicyEnforcer),
            1 => layers.into_iter().next().expect("checked len == 1"),
            _ => Arc::new(CompositeEnforcer::new(layers)),
        })
    }

    /// Apply a change to storage; return `true` if storage actually
    /// moved, `false` if it was a logical no-op (re-asserting an
    /// existing binding, deleting an absent id, etc.). The caller
    /// uses the flag to skip the enforcer rebuild + swap on no-ops
    /// so replayed events don't churn the published enforcer.
    // One arm per `RuleChange` variant (ten since M4b) — a flat
    // dispatch table, not tangled logic; splitting it would only scatter
    // the per-variant storage mutations across helpers.
    #[allow(clippy::too_many_lines)]
    fn apply_change(&mut self, change: RuleChange) -> bool {
        match change {
            RuleChange::TagAssigned { table, column, tag } => {
                let key = (table, column);
                let entry = self.columns.entry(key).or_default();
                if entry.iter().any(|t| t == &tag) {
                    false
                } else {
                    entry.push(tag);
                    true
                }
            }
            RuleChange::TagRemoved { table, column, tag } => {
                let key = (table, column);
                let Some(entry) = self.columns.get_mut(&key) else {
                    return false;
                };
                let before = entry.len();
                entry.retain(|t| t != &tag);
                let changed = entry.len() != before;
                if entry.is_empty() {
                    self.columns.remove(&key);
                }
                changed
            }
            RuleChange::PolicyUpserted(policy) => {
                // Treat byte-identical re-upsert as a no-op: same id,
                // same org, same tag, same group, same rule shape.
                // Equality is enforced via a cheap field-wise check
                // below since `Policy` doesn't impl `PartialEq` (Expr
                // doesn't either; we compare what we can and pessimize
                // when in doubt). The rule field comparison falls back
                // to a Debug-string match because `RuleType` carries
                // `Expr` and there's no cheap structural equality on
                // arbitrary `Expr` shapes — Debug is a stable enough
                // proxy for the "did the operator re-send the same
                // event?" idempotency check.
                let same_as_existing = self.policies.get(&policy.id).is_some_and(|existing| {
                    existing.id == policy.id
                        && existing.org == policy.org
                        && existing.tag == policy.tag
                        && existing.group == policy.group
                        && format!("{:?}", existing.rule) == format!("{:?}", policy.rule)
                });
                if same_as_existing {
                    false
                } else {
                    self.policies.insert(policy.id.clone(), policy);
                    true
                }
            }
            RuleChange::PolicyDeleted { policy_id } => self.policies.remove(&policy_id).is_some(),
            RuleChange::CertificationUpserted {
                table,
                column,
                certification,
            } => {
                let key = (table, column);
                let entry = self.certifications.entry(key).or_default();
                if entry.iter().any(|c| c == &certification) {
                    false
                } else {
                    entry.push(certification);
                    true
                }
            }
            RuleChange::CertificationDeleted {
                table,
                column,
                certification,
            } => {
                let key = (table, column);
                let Some(entry) = self.certifications.get_mut(&key) else {
                    return false;
                };
                let before = entry.len();
                entry.retain(|c| c != &certification);
                let changed = entry.len() != before;
                if entry.is_empty() {
                    self.certifications.remove(&key);
                }
                changed
            }
            RuleChange::MaskUpserted(mask) => {
                // One rule per (table, column, org) — the ColumnMaskingEnforcer
                // rejects duplicates on that triple, so replace in place rather
                // than append. The `org` is part of the identity of the rule
                //: two tenants may each mask the same
                // (table, column) under their own org, so an upsert must not
                // collapse them. `Expr` has no cheap structural equality, so a
                // Debug-string match stands in for the "same rule re-sent?"
                // idempotency check (identical to PolicyUpserted above).
                if let Some(existing) = self
                    .masks
                    .iter_mut()
                    .find(|m| m.table == mask.table && m.column == mask.column && m.org == mask.org)
                {
                    if format!("{:?}", existing.mask) == format!("{:?}", mask.mask) {
                        false
                    } else {
                        *existing = mask;
                        true
                    }
                } else {
                    self.masks.push(mask);
                    true
                }
            }
            RuleChange::MaskRemoved { table, column, org } => {
                let before = self.masks.len();
                self.masks
                    .retain(|m| !(m.table == table && m.column == column && m.org == org));
                self.masks.len() != before
            }
            RuleChange::RowFilterUpserted(filter) => {
                // One rule per (table, org) (RowFilterEnforcer rejects
                // duplicates on that pair); replace in place. The `org` is
                // part of the rule identity — distinct tenants may
                // filter the same table. Debug-string idempotency, as above.
                if let Some(existing) = self
                    .filters
                    .iter_mut()
                    .find(|f| f.table == filter.table && f.org == filter.org)
                {
                    if format!("{:?}", existing.predicate) == format!("{:?}", filter.predicate) {
                        false
                    } else {
                        *existing = filter;
                        true
                    }
                } else {
                    self.filters.push(filter);
                    true
                }
            }
            RuleChange::RowFilterRemoved { table, org } => {
                let before = self.filters.len();
                self.filters.retain(|f| !(f.table == table && f.org == org));
                self.filters.len() != before
            }
        }
    }
}

/// Trait surface for the slice-2 rule store. `InMemoryRuleStore` is
/// the MVP impl; a catalog-backed `PostgresRuleStore` (deferred per
/// spec 04 §"Out of scope") would implement the same trait.
pub trait RuleStore: Send + Sync + std::fmt::Debug + 'static {
    /// Apply a single change atomically. On success, the store's
    /// internal enforcer (returned by [`InMemoryRuleStore::enforcer`])
    /// reflects the new rule set on the next read.
    ///
    /// # Errors
    /// See [`ApplyError`]. The store's storage is *not* mutated when
    /// the resulting enforcer fails to rebuild — atomicity at the
    /// `apply` boundary.
    fn apply(&self, change: RuleChange) -> Result<(), ApplyError>;

    /// Borrow the current enforcer composed from the store's
    /// snapshot. Cheap — Arc-clone of the live `MutableEnforcer`
    /// publication.
    fn snapshot(&self) -> Arc<dyn PolicyEnforcer>;
}

/// Initial rule set for [`InMemoryRuleStore::new`].
///
/// All fields default to empty; the empty value produces a
/// `NoopPolicyEnforcer` on first `snapshot()`, identical to the
/// pre-slice-2 boot path when no rules are configured.
#[derive(Debug, Default)]
pub struct InitialRules {
    /// Static column-mask rules.
    pub masks: Vec<ColumnMask>,
    /// Static row-filter rules.
    pub filters: Vec<RowFilter>,
    /// Tag definitions known at boot.
    pub tags: Vec<TagDefinition>,
    /// Policies known at boot. The store keys them by `Policy::id`
    /// for the upsert/delete path.
    pub policies: Vec<Policy>,
    /// Tag bindings known at boot. Slice 2 keys by
    /// `(table, column)`; each entry's `tags` field is stored
    /// verbatim.
    pub columns: Vec<SemanticTableColumn>,
    /// Session default `(catalog, schema)` passed to the composed
    /// [`ColumnMaskingEnforcer`] so a fully-qualified (e.g.
    /// lineage-propagated) mask matches a bare query that resolves
    /// there. `None` ⇒ historical downgrade-only matching.
    pub session_defaults: Option<(String, String)>,
}

/// In-process [`RuleStore`] implementation.
///
/// Construct via [`Self::new`]; the constructor builds the initial
/// enforcer, wraps it in a [`MutableEnforcer`], and stores both. The
/// `MutableEnforcer` handle is what downstream code (server's
/// `PolicyOptimizerRule`) holds — calling `.current()` per query
/// is lock-free.
#[derive(Debug)]
pub struct InMemoryRuleStore {
    storage: RwLock<RuleStorage>,
    enforcer: Arc<MutableEnforcer>,
}

impl InMemoryRuleStore {
    /// Build a store from initial primitives.
    ///
    /// # Errors
    /// Returns an [`ApplyError`] if the initial rule set cannot
    /// compose into an enforcer — i.e. invalid tag/policy/column
    /// cross-references or duplicate mask/filter keys. Mirrors the
    /// existing boot-time validation in
    /// `dataglot-server::config::build_policy_enforcer`.
    pub fn new(initial: InitialRules) -> Result<Arc<Self>, ApplyError> {
        let mut storage = RuleStorage {
            masks: initial.masks,
            filters: initial.filters,
            tags: initial.tags,
            policies: HashMap::with_capacity(initial.policies.len()),
            columns: HashMap::with_capacity(initial.columns.len()),
            certifications: HashMap::new(),
            session_defaults: initial.session_defaults,
        };
        for p in initial.policies {
            storage.policies.insert(p.id.clone(), p);
        }
        for c in initial.columns {
            storage.columns.insert((c.table, c.column), c.tags);
        }

        let initial_enforcer = storage.compose()?;
        let mutable = Arc::new(MutableEnforcer::new(initial_enforcer));
        Ok(Arc::new(Self {
            storage: RwLock::new(storage),
            enforcer: mutable,
        }))
    }

    /// Cheap clone of the live `MutableEnforcer` handle. The server
    /// holds one for every session's `PolicyOptimizerRule`.
    #[must_use]
    pub fn enforcer(&self) -> Arc<MutableEnforcer> {
        Arc::clone(&self.enforcer)
    }
}

impl RuleStore for InMemoryRuleStore {
    // The write guard is held for the whole mutate-then-rebuild-then-swap
    // step *by design* (see comment below) so concurrent applies
    // serialise; tightening it would let an apply interleave between
    // `compose()` and `swap()`. This is intentional, not the
    // deadlock-prone over-hold `significant_drop_tightening` targets.
    #[allow(clippy::significant_drop_tightening)]
    fn apply(&self, change: RuleChange) -> Result<(), ApplyError> {
        // Hold the write lock for the *entire* mutate-then-rebuild
        // step so concurrent applies serialise. Readers go through
        // the MutableEnforcer, which doesn't touch this lock; the
        // only thing that contends is rebuild work, which is rare.
        let mut storage = self
            .storage
            .write()
            .expect("RuleStorage RwLock is poisoned");

        // Snapshot the *current* state before mutating so a build
        // failure on the new state rolls back cleanly. Cheap because
        // the vectors and HashMaps are small in practice (rule churn
        // is per-event, not per-row).
        let snapshot = (
            storage.masks.clone(),
            storage.filters.clone(),
            storage.tags.clone(),
            storage.policies.clone(),
            storage.columns.clone(),
            storage.certifications.clone(),
        );

        let changed = storage.apply_change(change);
        if !changed {
            // Replayed event or otherwise-idempotent no-op. Skip the
            // rebuild + swap so the published enforcer pointer
            // (which downstream code may compare with `Arc::ptr_eq`)
            // stays stable across replays.
            return Ok(());
        }

        let new_enforcer = match storage.compose() {
            Ok(e) => e,
            Err(err) => {
                // Roll storage back to the pre-apply snapshot so the
                // store's view of the world stays consistent with the
                // last published enforcer. The published enforcer
                // itself is unchanged because we haven't called
                // `.swap` yet.
                storage.masks = snapshot.0;
                storage.filters = snapshot.1;
                storage.tags = snapshot.2;
                storage.policies = snapshot.3;
                storage.columns = snapshot.4;
                storage.certifications = snapshot.5;
                return Err(err);
            }
        };

        // Publish. From this point on, every reader sees the new
        // enforcer. Reads in flight against the old one complete
        // safely against the old Arc.
        self.enforcer.swap(new_enforcer);

        Ok(())
    }

    fn snapshot(&self) -> Arc<dyn PolicyEnforcer> {
        self.enforcer.current()
    }
}

#[cfg(test)]
// Tests hold a lock guard to the end of the body to assert on its
// contents — harmless. `significant_drop_tightening` exists to prevent
// the over-held guards that cause production deadlocks, so relax it here.
#[allow(clippy::significant_drop_tightening)]
mod tests {
    use super::*;
    use crate::{Identity, OrgGroupId, RuleType};
    use datafusion::common::tree_node::Transformed;
    use datafusion::logical_expr::{col, lit, LogicalPlan, LogicalPlanBuilder};

    fn empty_plan() -> LogicalPlan {
        LogicalPlanBuilder::empty(true).build().expect("empty plan")
    }

    fn pii_tag() -> TagDefinition {
        TagDefinition {
            id: TagId::new("pii"),
            org: "acme".to_string(),
            name: "PII".to_string(),
        }
    }

    fn analyst_mask_policy() -> Policy {
        Policy {
            id: "mask-pii-analyst".to_string(),
            org: "acme".to_string(),
            tag: TagId::new("pii"),
            group: OrgGroupId::new("analyst"),
            rule: RuleType::Mask {
                expression: lit("***@example.com"),
            },
        }
    }

    fn analyst_filter_policy() -> Policy {
        Policy {
            id: "filter-pii-analyst".to_string(),
            org: "acme".to_string(),
            tag: TagId::new("pii"),
            group: OrgGroupId::new("analyst"),
            rule: RuleType::RowFilter {
                predicate: col("email").eq(lit("bob@example.com")),
            },
        }
    }

    /// Empty store snapshots to the noop enforcer — same boot shape
    /// as a server with no rules configured.
    #[test]
    fn empty_store_snapshots_to_noop_enforcer() {
        let store = InMemoryRuleStore::new(InitialRules::default()).expect("build");
        let enforcer = store.snapshot();
        // Rewriting an empty plan against the noop is a no-op.
        let Transformed { transformed, .. } = enforcer
            .rewrite(empty_plan(), &Identity::anonymous())
            .expect("noop rewrite");
        assert!(!transformed);
    }

    /// `PolicyUpserted` for a new tag rule survives a `snapshot()`
    /// roundtrip — the tag-based enforcer comes online once the
    /// policy and the tag/column bindings are all present.
    #[test]
    fn policy_upserted_then_tag_assigned_makes_enforcer_active() {
        let store = InMemoryRuleStore::new(InitialRules {
            tags: vec![pii_tag()],
            ..Default::default()
        })
        .expect("build");

        // Snapshot before any policy / column binding — no work
        // expected (no policy, no column).
        let pre = store.snapshot();
        let pre_id = Arc::as_ptr(&pre).cast::<()>();

        // Apply: register the mask policy.
        store
            .apply(RuleChange::PolicyUpserted(analyst_mask_policy()))
            .expect("upsert policy");
        // Apply: bind the PII tag to users.email.
        store
            .apply(RuleChange::TagAssigned {
                table: TableReference::bare("users"),
                column: "email".to_string(),
                tag: TagId::new("pii"),
            })
            .expect("assign tag");

        // Post-apply snapshot must be a *different* enforcer Arc
        // (we swapped twice).
        let post = store.snapshot();
        let post_id = Arc::as_ptr(&post).cast::<()>();
        assert_ne!(pre_id, post_id, "snapshot pointer must change after apply");
    }

    /// `TagAssigned` is idempotent — re-asserting the same binding
    /// twice doesn't duplicate the tag id in storage AND doesn't
    /// republish the enforcer (replayed events keep the snapshot
    /// pointer stable).
    #[test]
    fn tag_assigned_is_idempotent_and_skips_rebuild() {
        let store = InMemoryRuleStore::new(InitialRules {
            tags: vec![pii_tag()],
            ..Default::default()
        })
        .expect("build");

        let change = RuleChange::TagAssigned {
            table: TableReference::bare("users"),
            column: "email".to_string(),
            tag: TagId::new("pii"),
        };
        store.apply(change.clone()).expect("first");
        let after_first_ptr = Arc::as_ptr(&store.snapshot()).cast::<()>();

        store.apply(change).expect("second (no-op)");
        let after_second_ptr = Arc::as_ptr(&store.snapshot()).cast::<()>();

        let storage = store.storage.read().expect("read");
        let binding = storage
            .columns
            .get(&(TableReference::bare("users"), "email".to_string()))
            .expect("binding present");
        assert_eq!(binding.len(), 1, "duplicate binding must collapse");
        assert_eq!(
            after_first_ptr, after_second_ptr,
            "snapshot pointer must stay stable across an idempotent no-op apply"
        );
    }

    /// `TagRemoved` reverses `TagAssigned`. Removing an absent
    /// binding is a no-op.
    #[test]
    fn tag_removed_reverses_assignment_and_is_idempotent() {
        let store = InMemoryRuleStore::new(InitialRules {
            tags: vec![pii_tag()],
            ..Default::default()
        })
        .expect("build");

        let key = (TableReference::bare("users"), "email".to_string());
        store
            .apply(RuleChange::TagAssigned {
                table: key.0.clone(),
                column: key.1.clone(),
                tag: TagId::new("pii"),
            })
            .expect("assign");
        assert!(store.storage.read().unwrap().columns.contains_key(&key));

        store
            .apply(RuleChange::TagRemoved {
                table: key.0.clone(),
                column: key.1.clone(),
                tag: TagId::new("pii"),
            })
            .expect("remove");
        assert!(
            !store.storage.read().unwrap().columns.contains_key(&key),
            "binding must be gone after the last tag is removed"
        );

        // Second remove is a no-op.
        store
            .apply(RuleChange::TagRemoved {
                table: key.0.clone(),
                column: key.1.clone(),
                tag: TagId::new("pii"),
            })
            .expect("second remove no-op");
    }

    /// `PolicyDeleted` removes the named policy and the next snapshot
    /// reflects the absence.
    #[test]
    fn policy_deleted_removes_by_id() {
        let store = InMemoryRuleStore::new(InitialRules {
            tags: vec![pii_tag()],
            policies: vec![analyst_mask_policy(), analyst_filter_policy()],
            ..Default::default()
        })
        .expect("build");

        store
            .apply(RuleChange::PolicyDeleted {
                policy_id: "filter-pii-analyst".to_string(),
            })
            .expect("delete");

        let storage = store.storage.read().expect("read");
        assert!(storage.policies.contains_key("mask-pii-analyst"));
        assert!(!storage.policies.contains_key("filter-pii-analyst"));
    }

    /// `CertificationUpserted` / `CertificationDeleted` round-trip
    /// through the sidecar storage. Slice 2 doesn't gate enforcement
    /// on certifications; the test pins the storage shape so slice 3+
    /// can rely on it.
    #[test]
    fn certification_round_trip() {
        let store = InMemoryRuleStore::new(InitialRules::default()).expect("build");
        let key = (TableReference::bare("users"), "email".to_string());

        store
            .apply(RuleChange::CertificationUpserted {
                table: key.0.clone(),
                column: key.1.clone(),
                certification: "steward.alice".to_string(),
            })
            .expect("upsert cert");

        assert_eq!(
            store
                .storage
                .read()
                .unwrap()
                .certifications
                .get(&key)
                .map(Vec::as_slice),
            Some(&["steward.alice".to_string()][..])
        );

        store
            .apply(RuleChange::CertificationDeleted {
                table: key.0.clone(),
                column: key.1.clone(),
                certification: "steward.alice".to_string(),
            })
            .expect("delete cert");

        assert!(!store
            .storage
            .read()
            .unwrap()
            .certifications
            .contains_key(&key));
    }

    ///  M4b: `MaskUpserted` adds a static, unconditional column
    /// mask to the live store (the `CREATE MASK` path), and the next
    /// `snapshot()` actually masks the column; `MaskRemoved` reverses it.
    #[tokio::test]
    async fn mask_upserted_then_removed_enforces_and_reverses() {
        use datafusion::arrow::array::StringArray;
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;
        use datafusion::prelude::SessionContext;

        // Run `SELECT email FROM users` through the store's current
        // enforcer and return the (possibly masked) single value. Declared
        // before any statement (clippy::items_after_statements).
        async fn email_value(ctx: &SessionContext, store: &InMemoryRuleStore) -> String {
            let plan = ctx
                .sql("SELECT email FROM users")
                .await
                .unwrap()
                .logical_plan()
                .clone();
            let rewritten = store
                .snapshot()
                .rewrite(plan, &Identity::anonymous())
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

        let schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            DataType::Utf8,
            false,
        )]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(StringArray::from(vec!["real@x.com"]))],
        )
        .unwrap();
        let ctx = SessionContext::new();
        ctx.register_table(
            "users",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();

        let store = InMemoryRuleStore::new(InitialRules::default()).expect("build");
        // No mask yet — the email comes back raw.
        assert_eq!(email_value(&ctx, &store).await, "real@x.com");

        store
            .apply(RuleChange::MaskUpserted(ColumnMask {
                table: TableReference::bare("users"),
                column: "email".to_string(),
                mask: lit("***@example.com"),
                org: None,
                groups: None,
            }))
            .expect("upsert mask");
        assert_eq!(
            email_value(&ctx, &store).await,
            "***@example.com",
            "CREATE MASK must enforce"
        );

        store
            .apply(RuleChange::MaskRemoved {
                table: TableReference::bare("users"),
                column: "email".to_string(),
                org: None,
            })
            .expect("remove mask");
        assert_eq!(
            email_value(&ctx, &store).await,
            "real@x.com",
            "DROP MASK must unmask"
        );
    }

    /// A byte-identical `MaskUpserted` re-apply is an idempotent no-op —
    /// the published enforcer pointer stays stable (replay safety).
    #[test]
    fn mask_upserted_is_idempotent() {
        let store = InMemoryRuleStore::new(InitialRules::default()).expect("build");
        let change = RuleChange::MaskUpserted(ColumnMask {
            table: TableReference::bare("users"),
            column: "email".to_string(),
            mask: lit("***"),
            org: None,
            groups: None,
        });
        store.apply(change.clone()).expect("first");
        let first = Arc::as_ptr(&store.snapshot()).cast::<()>();
        store.apply(change).expect("second (no-op)");
        let second = Arc::as_ptr(&store.snapshot()).cast::<()>();
        assert_eq!(first, second, "identical re-upsert must not republish");
        assert_eq!(store.storage.read().unwrap().masks.len(), 1);
    }

    /// `RowFilterUpserted` adds/replaces a row filter by table;
    /// `RowFilterRemoved` reverses it. Storage-level (the rewrite path is
    /// covered by the mask test above).
    #[test]
    fn row_filter_upserted_then_removed_round_trip() {
        let store = InMemoryRuleStore::new(InitialRules::default()).expect("build");
        store
            .apply(RuleChange::RowFilterUpserted(RowFilter {
                table: TableReference::bare("orders"),
                predicate: col("tenant_id").eq(lit("acme")),
                org: None,
                groups: None,
            }))
            .expect("upsert filter");
        assert_eq!(store.storage.read().unwrap().filters.len(), 1);

        // Replace-by-table: a second filter on the same table overwrites.
        store
            .apply(RuleChange::RowFilterUpserted(RowFilter {
                table: TableReference::bare("orders"),
                predicate: col("active").eq(lit(true)),
                org: None,
                groups: None,
            }))
            .expect("replace filter");
        assert_eq!(
            store.storage.read().unwrap().filters.len(),
            1,
            "same-table upsert must replace, not append (RowFilterEnforcer rejects dups)"
        );

        store
            .apply(RuleChange::RowFilterRemoved {
                table: TableReference::bare("orders"),
                org: None,
            })
            .expect("remove filter");
        assert!(store.storage.read().unwrap().filters.is_empty());
        // Removing an absent filter is a no-op.
        store
            .apply(RuleChange::RowFilterRemoved {
                table: TableReference::bare("orders"),
                org: None,
            })
            .expect("idempotent remove");
    }

    /// A `PolicyUpserted` whose tag is unknown surfaces
    /// [`ApplyError::BuildGovernance`] at the apply boundary AND
    /// rolls storage back to the pre-apply state. The next
    /// `snapshot()` still returns the pre-apply enforcer pointer.
    #[test]
    fn apply_failure_rolls_back_and_keeps_published_enforcer() {
        let store = InMemoryRuleStore::new(InitialRules::default()).expect("build");
        let pre_snapshot_ptr = Arc::as_ptr(&store.snapshot()).cast::<()>();

        // Reference a tag that wasn't defined — OrgGovernance builder
        // rejects at build() time.
        let unknown_tag_policy = Policy {
            id: "unknown".to_string(),
            org: "acme".to_string(),
            tag: TagId::new("does_not_exist"),
            group: OrgGroupId::new("analyst"),
            rule: RuleType::Mask {
                expression: lit("***"),
            },
        };
        let err = store
            .apply(RuleChange::PolicyUpserted(unknown_tag_policy))
            .expect_err("must error");
        assert!(
            matches!(err, ApplyError::BuildGovernance(_)),
            "expected BuildGovernance, got: {err:?}"
        );

        // Storage must NOT contain the failed-upsert id — rolled back.
        assert!(
            store.storage.read().unwrap().policies.is_empty(),
            "storage must be rolled back after a failed compose"
        );

        // Published enforcer pointer unchanged — the swap never ran.
        let post_snapshot_ptr = Arc::as_ptr(&store.snapshot()).cast::<()>();
        assert_eq!(
            pre_snapshot_ptr, post_snapshot_ptr,
            "MutableEnforcer must not advance on failed apply"
        );
    }

    /// /36: `InitialRules.session_defaults` must be applied by
    /// `compose()` when it builds the `ColumnMaskingEnforcer`, so a
    /// fully-qualified mask matches a bare query that resolves to those
    /// defaults. `apply()`-triggered rebuilds run the *same* `compose()`,
    /// so this also guards the rebuild path (flagged in #489 review).
    #[tokio::test]
    async fn session_defaults_applied_by_composed_enforcer() {
        use datafusion::arrow::array::StringArray;
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;
        use datafusion::prelude::SessionContext;

        let schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            DataType::Utf8,
            false,
        )]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(StringArray::from(vec!["real@x.com"]))],
        )
        .unwrap();
        let ctx = SessionContext::new(); // default catalog/schema = datafusion.public
        ctx.register_table(
            "users",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();

        let store = InMemoryRuleStore::new(InitialRules {
            masks: vec![ColumnMask {
                table: TableReference::full("datafusion", "public", "users"),
                column: "email".to_string(),
                mask: lit("***@example.com"),
                org: None,
                groups: None,
            }],
            session_defaults: Some(("datafusion".to_string(), "public".to_string())),
            ..Default::default()
        })
        .expect("store builds");

        // Bare query — only the session-default *upgrade* lets the
        // fully-qualified mask fire. If compose() dropped session_defaults,
        // the email comes back raw.
        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .unwrap()
            .logical_plan()
            .clone();
        let rewritten = store
            .snapshot()
            .rewrite(plan, &Identity::anonymous())
            .expect("rewrite")
            .data;
        let batches = ctx
            .execute_logical_plan(rewritten)
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
        assert_eq!(
            col.value(0),
            "***@example.com",
            "session_defaults must let the composed enforcer mask a bare query via the full mask"
        );
    }

    ///  F4: two org-tagged masks on the **same** `(table, column)`
    /// coexist in a single store (the shape `load_persisted_policies`
    /// produces when it loads every org into one `InMemoryRuleStore`), and
    /// the composed enforcer masks per-org — acme sees acme's mask, beta
    /// sees beta's, and neither leaks to the other tenant.
    #[tokio::test]
    async fn org_tagged_masks_coexist_and_enforce_per_org() {
        use datafusion::arrow::array::StringArray;
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;
        use datafusion::prelude::SessionContext;

        async fn email_for(
            ctx: &SessionContext,
            store: &InMemoryRuleStore,
            id: &Identity,
        ) -> String {
            let plan = ctx
                .sql("SELECT email FROM users")
                .await
                .unwrap()
                .logical_plan()
                .clone();
            let rewritten = store.snapshot().rewrite(plan, id).expect("rewrite").data;
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

        let schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            DataType::Utf8,
            false,
        )]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(StringArray::from(vec!["real@x.com"]))],
        )
        .unwrap();
        let ctx = SessionContext::new();
        ctx.register_table(
            "users",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();

        // Seed two org-tagged masks on the same (table, column).
        let store = InMemoryRuleStore::new(InitialRules {
            masks: vec![
                ColumnMask {
                    table: TableReference::bare("users"),
                    column: "email".to_string(),
                    mask: lit("ACME"),
                    org: Some("acme".to_string()),
                    groups: None,
                },
                ColumnMask {
                    table: TableReference::bare("users"),
                    column: "email".to_string(),
                    mask: lit("BETA"),
                    org: Some("beta".to_string()),
                    groups: None,
                },
            ],
            ..Default::default()
        })
        .expect("store builds with two org-tagged masks on the same key");

        let acme = Identity::user("a").with_org("acme");
        let beta = Identity::user("b").with_org("beta");
        assert_eq!(email_for(&ctx, &store, &acme).await, "ACME");
        assert_eq!(email_for(&ctx, &store, &beta).await, "BETA");
        // A third org / anonymous sees no tenant mask → raw value.
        assert_eq!(
            email_for(&ctx, &store, &Identity::anonymous()).await,
            "real@x.com"
        );
    }
}
