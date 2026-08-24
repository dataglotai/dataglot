//! Lineage-propagated mask enforcement — §11 Interface 4.
//!
//! Closes the governance loop: a column-mask configured on a
//! *source* column is automatically extended to every *derived*
//! column that descends from it through the column-lineage graph,
//! so a single source classification covers the whole derived
//! graph with **no** re-tagging of derived products.
//!
//! This is the composition seam between lineage and policy:
//! [`dataglot_core::lineage::LineageGraph`] (the descendant query)
//! and [`dataglot_policy::ColumnMask`] (the enforcement rule). It
//! lives in `dataglot-server` because that is the only crate that
//! depends on both — `dataglot-policy` does not depend on
//! `dataglot-core` (rule 4), so the bridge cannot live there. This
//! mirrors `MaskedColumns` in [`crate::lineage`].
//!
//! # Resolution model (spec decisions 1 & 2)
//!
//! Propagation is a pure function of `(configured masks, lineage
//! graph)`. The expansion is recomputed whenever the enforcer is
//! rebuilt (which is whenever masks change), so enforcement stays a
//! function of current state — no eagerly-materialized propagated
//! tags to keep coherent. The graph is the internal source of truth
//! (no synchronous external call on the plan-time hot path).
//!
//! # Aggregation semantics (decision 4)
//!
//! Propagation follows the lineage graph's traversal rules: a tag
//! propagates through value-preserving transforms and GROUP BY keys
//! but **not** through aggregate outputs by default (a `SUM` is not
//! the masked value). Callers opt in via
//! `propagate_through_aggregation` for stricter regimes.

use std::collections::HashSet;

use datafusion::common::TableReference;
use dataglot_core::lineage::{DatasetRef, LineageGraph};
use dataglot_policy::ColumnMask;

/// Normalise a `TableReference` to the three-part [`DatasetRef`]
/// the lineage graph keys nodes by — mirroring the `dataset_of`
/// normalisation `column_lineage` applies to table scans (missing
/// catalog/schema default to `"default"` / `"public"`). A mask and
/// a derived product that reference the same table with the same
/// qualification therefore resolve to the same graph node.
pub(crate) fn dataset_of(table: &TableReference) -> DatasetRef {
    DatasetRef {
        catalog: table.catalog().unwrap_or("default").to_string(),
        schema: table.schema().unwrap_or("public").to_string(),
        table: table.table().to_string(),
    }
}

/// Whether a configured mask's table reference matches a lineage
/// **source node**, with the same leniency the enforcer's
/// `match_candidates` applies: a mask that omits the catalog/schema
/// matches a source in *any* catalog/schema (a bare `users` mask
/// matches `pg.public.users`). This decouples how the operator wrote
/// the mask from how the derived product's SQL referenced the source
/// — the qualification mismatch behind.
pub(crate) fn mask_matches_source(mask: &TableReference, source: &DatasetRef) -> bool {
    mask.table() == source.table
        && mask.schema().is_none_or(|s| s == source.schema)
        && mask.catalog().is_none_or(|c| c == source.catalog)
}

/// Expand `configured` masks to also cover every derived column that
/// descends from a masked source column, per `graph`.
///
/// The result is the configured masks plus one derived mask per
/// lineage descendant, reusing the source mask's expression. Derived
/// masks are keyed by the descendant's **fully-qualified**
/// `(catalog, schema, table)` — *not* the bare table name. Bare
/// keying would collide across catalogs/schemas (two `tenant_a.v`
/// and `tenant_b.v` derived from different masked sources would
/// drop one in dedup and let the survivor mask the other tenant's
/// table — ). Full qualification keeps them distinct; the
/// enforcer's `match_candidates` still matches a query that
/// resolves to that full reference. Duplicate fully-qualified
/// `(dataset, column)` pairs are dropped — a configured mask always
/// wins over a propagated one.
///
/// `propagate_through_aggregation` is threaded to
/// [`LineageGraph::descendants`]: `false` (the default) stops at
/// aggregate outputs (decision 4).
#[must_use]
pub fn propagate_masks(
    configured: &[ColumnMask],
    graph: &LineageGraph,
    propagate_through_aggregation: bool,
) -> Vec<ColumnMask> {
    let mut out: Vec<ColumnMask> = configured.to_vec();
    // Fully-qualified (dataset, column) pairs already covered —
    // seed with the configured masks (normalised to their full
    // DatasetRef) so a propagated edge never shadows a
    // hand-configured rule and same-name-different-catalog
    // descendants never collide.
    let mut seen: HashSet<(DatasetRef, String)> = configured
        .iter()
        .map(|m| (dataset_of(&m.table), m.column.clone()))
        .collect();

    for mask in configured {
        // Match the mask against the graph's *actual* source nodes
        // (leniently), rather than guessing the exact qualification the
        // planner gave the source scan — that guess was 's bug.
        let matched = graph.source_fields().filter(|src| {
            src.field == mask.column && mask_matches_source(&mask.table, &src.dataset)
        });
        for source in matched {
            for desc in graph.descendants(source, propagate_through_aggregation) {
                let key = (desc.dataset.clone(), desc.field.clone());
                if seen.insert(key) {
                    out.push(ColumnMask {
                        table: TableReference::full(
                            desc.dataset.catalog.clone(),
                            desc.dataset.schema.clone(),
                            desc.dataset.table.clone(),
                        ),
                        column: desc.field.clone(),
                        mask: mask.mask.clone(),
                        // A propagated mask inherits the source mask's org
                        //: a tenant-scoped source mask stays
                        // tenant-scoped on its derived columns; an
                        // operator-wide (`None`) one stays operator-wide.
                        org: mask.org.clone(),
                        groups: None,
                    });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use datafusion::arrow::array::{RecordBatch, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::datasource::MemTable;
    use datafusion::execution::session_state::SessionStateBuilder;
    use datafusion::logical_expr::lit;
    use datafusion::optimizer::OptimizerRule;
    use datafusion::prelude::SessionContext;
    use dataglot_core::lineage::{
        column_lineage, ColumnLineage, FieldRef, InputFieldContribution, OutputFieldLineage,
        TransformationType,
    };
    use dataglot_policy::{ColumnMaskingEnforcer, PolicyOptimizerRule};

    fn dref(table: &str) -> DatasetRef {
        DatasetRef {
            catalog: "default".into(),
            schema: "public".into(),
            table: table.into(),
        }
    }

    fn one_col(
        output: &str,
        src_table: &str,
        src_field: &str,
        transform: TransformationType,
    ) -> ColumnLineage {
        ColumnLineage {
            fields: vec![OutputFieldLineage {
                output_field: output.into(),
                inputs: vec![InputFieldContribution {
                    field: FieldRef {
                        dataset: dref(src_table),
                        field: src_field.into(),
                    },
                    transform,
                    masking: false,
                }],
            }],
        }
    }

    fn email_mask() -> ColumnMask {
        ColumnMask {
            table: TableReference::bare("users"),
            column: "email".into(),
            mask: lit("***@example.com"),
            org: None,
            groups: None,
        }
    }

    #[test]
    fn propagates_mask_to_identity_descendant() {
        // users.email masked; view v.email derives from it (IDENTITY).
        let mut g = LineageGraph::new();
        g.add_product(
            &dref("v"),
            &one_col("email", "users", "email", TransformationType::Identity),
        );
        let expanded = propagate_masks(&[email_mask()], &g, false);

        assert_eq!(expanded.len(), 2, "configured + one propagated mask");
        let v = expanded
            .iter()
            .find(|m| m.table.table() == "v")
            .expect("propagated mask on v");
        assert_eq!(v.column, "email");
        assert_eq!(
            format!("{:?}", v.mask),
            format!("{:?}", lit("***@example.com"))
        );
    }

    #[test]
    fn does_not_propagate_through_aggregation_by_default() {
        // revenue.total = SUM(users.email-ish) — aggregate output.
        let mut g = LineageGraph::new();
        g.add_product(
            &dref("revenue"),
            &one_col("total", "users", "email", TransformationType::Aggregation),
        );
        assert_eq!(
            propagate_masks(&[email_mask()], &g, false).len(),
            1,
            "aggregate descendant must not inherit the mask by default"
        );
        assert_eq!(
            propagate_masks(&[email_mask()], &g, true).len(),
            2,
            "strict regime opts into aggregate propagation"
        );
    }

    #[test]
    fn configured_mask_wins_over_propagated_duplicate() {
        // A view column that both descends from a masked source AND is
        // itself explicitly masked must not produce a duplicate rule.
        let mut g = LineageGraph::new();
        g.add_product(
            &dref("v"),
            &one_col("email", "users", "email", TransformationType::Identity),
        );
        let v_mask = ColumnMask {
            table: TableReference::bare("v"),
            column: "email".into(),
            mask: lit("REDACTED"),
            org: None,
            groups: None,
        };
        let expanded = propagate_masks(&[email_mask(), v_mask], &g, false);
        let on_v: Vec<_> = expanded.iter().filter(|m| m.table.table() == "v").collect();
        assert_eq!(on_v.len(), 1, "exactly one rule on v.email");
        assert_eq!(
            format!("{:?}", on_v[0].mask),
            format!("{:?}", lit("REDACTED")),
            "the configured rule wins over the propagated one"
        );
    }

    #[test]
    fn no_masks_or_empty_graph_is_identity() {
        let g = LineageGraph::new();
        assert!(propagate_masks(&[], &g, false).is_empty());
        assert_eq!(propagate_masks(&[email_mask()], &g, false).len(), 1);
    }

    /// End-to-end: derive `v.email`'s lineage from its defining query,
    /// propagate the `users.email` mask through the graph, then query
    /// the *derived* view `v` and assert the descendant column comes
    /// back masked — with no mask ever configured on `v`. This is the
    /// Interface 4 exit-criterion behaviour at the plan level.
    #[tokio::test]
    async fn derived_view_column_is_masked_via_propagation() {
        // 1. Compute v's column lineage from its defining query.
        let lineage_ctx = SessionContext::new();
        let users_schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            DataType::Utf8,
            false,
        )]));
        let users_batch = RecordBatch::try_new(
            users_schema.clone(),
            vec![Arc::new(StringArray::from(vec!["real@x.com"]))],
        )
        .unwrap();
        lineage_ctx
            .register_table(
                "users",
                Arc::new(MemTable::try_new(users_schema, vec![vec![users_batch]]).unwrap()),
            )
            .unwrap();
        let v_plan = lineage_ctx
            .sql("SELECT email FROM users")
            .await
            .unwrap()
            .logical_plan()
            .clone();
        let v_lineage = column_lineage(&v_plan).unwrap();

        // 2. Build the graph + propagate the source mask. The
        //    product is registered under DataFusion's real default
        //    catalog/schema so the propagated full-qualified mask
        //    can match the query's resolved reference.
        let mut graph = LineageGraph::new();
        let v_dataset = DatasetRef {
            catalog: "datafusion".into(),
            schema: "public".into(),
            table: "v".into(),
        };
        graph.add_product(&v_dataset, &v_lineage);
        let expanded = propagate_masks(&[email_mask()], &graph, false);
        let enforcer = Arc::new(ColumnMaskingEnforcer::new(expanded).expect("build enforcer"));

        // 3. Query the derived view `v` through a session carrying the
        //    propagated enforcer. `v` itself was never masked directly.
        //    The policy rule must be *prepended* (run before projection
        //    pushdown collapses Projection→TableScan), mirroring
        //    `DataglotServer::create_session`.
        let base = SessionContext::new();
        let base_state = base.state();
        let mut rules: Vec<Arc<dyn OptimizerRule + Send + Sync>> = base_state.optimizers().to_vec();
        rules.insert(0, Arc::new(PolicyOptimizerRule::new(enforcer)));
        let state = SessionStateBuilder::new_from_existing(base_state)
            .with_optimizer_rules(rules)
            .build();
        let ctx = SessionContext::new_with_state(state);
        let v_schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            DataType::Utf8,
            false,
        )]));
        let v_batch = RecordBatch::try_new(
            v_schema.clone(),
            vec![Arc::new(StringArray::from(vec!["real@x.com"]))],
        )
        .unwrap();
        ctx.register_table(
            "v",
            Arc::new(MemTable::try_new(v_schema, vec![vec![v_batch]]).unwrap()),
        )
        .unwrap();

        // Query the derived product by its fully-qualified name. The
        // propagated mask is keyed by the descendant's full
        // (catalog, schema, table) — collision-safe across catalogs
        // — and matches a query that resolves to that full
        // reference. (Enforcing on a *bare*-written query against a
        // full-qualified propagated mask needs the enforcer to
        // upgrade the query ref to its session-resolved qualification
        // — tracked in, lands with the live wiring.)
        let batches = ctx
            .sql("SELECT email FROM datafusion.public.v")
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
            "derived product column must be masked via lineage propagation, not direct config"
        );
    }

    #[test]
    fn full_qualification_keeps_same_name_products_distinct_across_catalogs() {
        //  regression: two derived products both named `v`, in
        // different catalogs, each descending from a *different*
        // masked source with a *different* mask. Bare-table keying
        // would collide (drop one in dedup, or let one mask the
        // other's table). Full qualification keeps them distinct.
        let src_a = ColumnMask {
            table: TableReference::full("tenant_a", "public", "src"),
            column: "email".into(),
            mask: lit("AAA"),
            org: None,
            groups: None,
        };
        let src_b = ColumnMask {
            table: TableReference::full("tenant_b", "public", "src"),
            column: "email".into(),
            mask: lit("BBB"),
            org: None,
            groups: None,
        };
        let lineage_a = ColumnLineage {
            fields: vec![OutputFieldLineage {
                output_field: "email".into(),
                inputs: vec![InputFieldContribution {
                    field: FieldRef {
                        dataset: DatasetRef {
                            catalog: "tenant_a".into(),
                            schema: "public".into(),
                            table: "src".into(),
                        },
                        field: "email".into(),
                    },
                    transform: TransformationType::Identity,
                    masking: false,
                }],
            }],
        };
        let lineage_b = ColumnLineage {
            fields: vec![OutputFieldLineage {
                output_field: "email".into(),
                inputs: vec![InputFieldContribution {
                    field: FieldRef {
                        dataset: DatasetRef {
                            catalog: "tenant_b".into(),
                            schema: "public".into(),
                            table: "src".into(),
                        },
                        field: "email".into(),
                    },
                    transform: TransformationType::Identity,
                    masking: false,
                }],
            }],
        };
        let mut g = LineageGraph::new();
        g.add_product(
            &DatasetRef {
                catalog: "tenant_a".into(),
                schema: "public".into(),
                table: "v".into(),
            },
            &lineage_a,
        );
        g.add_product(
            &DatasetRef {
                catalog: "tenant_b".into(),
                schema: "public".into(),
                table: "v".into(),
            },
            &lineage_b,
        );

        let expanded = propagate_masks(&[src_a, src_b], &g, false);
        // Both propagated v.email masks survive, distinct by catalog.
        let v_a = expanded
            .iter()
            .find(|m| m.table.catalog() == Some("tenant_a") && m.table.table() == "v")
            .expect("tenant_a.v mask present");
        let v_b = expanded
            .iter()
            .find(|m| m.table.catalog() == Some("tenant_b") && m.table.table() == "v")
            .expect("tenant_b.v mask present (not dropped by dedup)");
        assert_eq!(format!("{:?}", v_a.mask), format!("{:?}", lit("AAA")));
        assert_eq!(
            format!("{:?}", v_b.mask),
            format!("{:?}", lit("BBB")),
            "each tenant's derived column keeps its own source mask — no cross-catalog conflation"
        );
    }

    #[test]
    fn propagates_bare_mask_through_qualified_source() {
        //  regression: the derived product's source lives in a
        // federated catalog (`pg.public.users`), but the operator wrote a
        // BARE config mask (`users.email`). The old exact-match resolved the
        // bare mask to `default.public.users` and found no descendants —
        // silently failing to propagate. Lenient source matching (a bare
        // mask matches a source in any catalog) fixes it.
        let mut g = LineageGraph::new();
        let lineage = ColumnLineage {
            fields: vec![OutputFieldLineage {
                output_field: "email".into(),
                inputs: vec![InputFieldContribution {
                    field: FieldRef {
                        dataset: DatasetRef {
                            catalog: "pg".into(),
                            schema: "public".into(),
                            table: "users".into(),
                        },
                        field: "email".into(),
                    },
                    transform: TransformationType::Identity,
                    masking: false,
                }],
            }],
        };
        g.add_product(
            &DatasetRef {
                catalog: "pg".into(),
                schema: "public".into(),
                table: "v".into(),
            },
            &lineage,
        );
        let bare = ColumnMask {
            table: TableReference::bare("users"),
            column: "email".into(),
            mask: lit("***@example.com"),
            org: None,
            groups: None,
        };
        let expanded = propagate_masks(&[bare], &g, false);
        let v = expanded
            .iter()
            .find(|m| m.table.table() == "v")
            .expect("bare mask must propagate to a qualified-source descendant");
        assert_eq!(
            v.table.catalog(),
            Some("pg"),
            "propagated mask keyed by the product's real catalog"
        );
        assert_eq!(v.column, "email");

        // A *qualified* mask for a different catalog must NOT match.
        let wrong = ColumnMask {
            table: TableReference::full("other", "public", "users"),
            column: "email".into(),
            mask: lit("X"),
            org: None,
            groups: None,
        };
        assert_eq!(
            propagate_masks(&[wrong], &g, false).len(),
            1,
            "a mask qualified to a different catalog must not propagate"
        );
    }
}
