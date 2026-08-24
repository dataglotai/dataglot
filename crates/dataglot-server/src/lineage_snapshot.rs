//! Boot-time lineage snapshot for the observability endpoint.
//!
//! [`crate::server::DataglotServer::new`] plans every configured derived
//! product once to build the column-lineage graph that drives mask
//! propagation (/34) — and until now the graph was consumed by
//! the rule store and discarded, invisible to operators. This module
//! freezes it into a serializable snapshot served at `GET /lineage`
//! on the observability listener, so the propagation thesis ("a mask
//! on `users.email` extends to every derived column that descends
//! from it") is inspectable as a graph instead of an act of faith.
//!
//! The snapshot is pure boot-time data: derived products are declared
//! in config and planned once at startup, so there is nothing to
//! refresh at request time. Masks that later change via the
//! governance webhook are *not* re-overlaid — the snapshot documents
//! the boot-time configuration, which is also what the demo and
//! testbench show. (Live rule state remains the enforcer's job.)

use serde::Serialize;

use dataglot_core::lineage::{FieldRef, LineageGraph};
use dataglot_policy::ColumnMask;

use crate::config::DerivedProductConfig;
use crate::propagation::{dataset_of, mask_matches_source, propagate_masks};

/// One dataset column in the lineage graph.
#[derive(Debug, Clone, Serialize)]
pub struct LineageNode {
    /// Catalog the column's dataset resolves under.
    pub catalog: String,
    /// Schema the column's dataset resolves under.
    pub schema: String,
    /// Table (or derived-product) name.
    pub table: String,
    /// Column name.
    pub field: String,
    /// `"derived"` when the column belongs to a declared derived
    /// product; `"source"` otherwise.
    pub kind: &'static str,
    /// `Some("configured")` when a config mask covers this column,
    /// `Some("propagated")` when it is masked only through lineage
    /// propagation, `None` when unmasked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<&'static str>,
}

/// A directed lineage edge between two [`LineageNode`]s, by index.
#[derive(Debug, Clone, Serialize)]
pub struct LineageEdgeView {
    /// Index of the source column in `nodes`.
    pub from: usize,
    /// Index of the derived column in `nodes`.
    pub to: usize,
    /// `"identity"` | `"transformation"` | `"aggregation"` — mirrors
    /// [`dataglot_core::lineage::TransformationType`]. Aggregation
    /// edges do not propagate masks (decision 4), which the lineage
    /// view renders differently.
    pub transform: &'static str,
}

/// A declared derived product, with whether boot-time planning
/// succeeded (a product that failed to plan is skipped best-effort —
/// masks won't propagate to it, and the view should say so).
#[derive(Debug, Clone, Serialize)]
pub struct ProductSummary {
    /// Product table name (as referenced in queries).
    pub name: String,
    /// Catalog the product resolves under (defaults applied).
    pub catalog: String,
    /// Schema the product resolves under (defaults applied).
    pub schema: String,
    /// The defining query.
    pub sql: String,
    /// Whether boot-time planning succeeded (contributed graph nodes).
    pub planned: bool,
}

/// The full serializable lineage view: declared products, every
/// column node, and the directed edges between them.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LineageSnapshot {
    /// Declared derived products (planned or not).
    pub products: Vec<ProductSummary>,
    /// Every column that appears in the graph.
    pub nodes: Vec<LineageNode>,
    /// Directed lineage edges between `nodes`, by index.
    pub edges: Vec<LineageEdgeView>,
}

/// Freeze `graph` + the configured masks into a [`LineageSnapshot`].
///
/// Mask annotation replays the exact propagation the rule store uses
/// ([`propagate_masks`], aggregation excluded), so the view and the
/// enforcer can never disagree about which derived columns are
/// covered.
pub(crate) fn build_lineage_snapshot(
    graph: &LineageGraph,
    products: &[DerivedProductConfig],
    configured_masks: &[ColumnMask],
    default_catalog: &str,
    default_schema: &str,
) -> LineageSnapshot {
    use std::collections::HashMap;

    // Stable node indexing: sources and derived fields in edge order,
    // deduped.
    let mut index: HashMap<FieldRef, usize> = HashMap::new();
    let mut nodes: Vec<FieldRef> = Vec::new();
    let mut edges: Vec<(usize, usize, &'static str)> = Vec::new();
    for (from, to, transform) in graph.edges() {
        let mut idx_of = |f: &FieldRef| {
            *index.entry(f.clone()).or_insert_with(|| {
                nodes.push(f.clone());
                nodes.len() - 1
            })
        };
        let from_ix = idx_of(from);
        let to_ix = idx_of(to);
        edges.push((
            from_ix,
            to_ix,
            match transform {
                dataglot_core::lineage::TransformationType::Identity => "identity",
                dataglot_core::lineage::TransformationType::Transformation => "transformation",
                dataglot_core::lineage::TransformationType::Aggregation => "aggregation",
            },
        ));
    }

    // Derived datasets = the declared products, qualified the same way
    // `build_lineage_graph` qualified them when registering.
    let product_refs: Vec<(dataglot_core::lineage::DatasetRef, &DerivedProductConfig)> = products
        .iter()
        .map(|p| {
            (
                dataglot_core::lineage::DatasetRef {
                    catalog: p
                        .catalog
                        .clone()
                        .unwrap_or_else(|| default_catalog.to_string()),
                    schema: p
                        .schema
                        .clone()
                        .unwrap_or_else(|| default_schema.to_string()),
                    table: p.name.clone(),
                },
                p,
            )
        })
        .collect();

    // Propagated rules beyond the configured prefix (propagate_masks
    // returns configured ++ propagated, configured first).
    let all_rules = propagate_masks(configured_masks, graph, false);
    let propagated_rules = &all_rules[configured_masks.len()..];

    let node_views: Vec<LineageNode> = nodes
        .iter()
        .map(|f| {
            let kind = if product_refs.iter().any(|(d, _)| *d == f.dataset) {
                "derived"
            } else {
                "source"
            };
            // Configured masks match leniently (a bare `users` mask
            // covers `pg.public.users`); propagated rules are always
            // fully qualified, so they match exactly.
            let mask = if configured_masks
                .iter()
                .any(|m| m.column == f.field && mask_matches_source(&m.table, &f.dataset))
            {
                Some("configured")
            } else if propagated_rules
                .iter()
                .any(|m| m.column == f.field && dataset_of(&m.table) == f.dataset)
            {
                Some("propagated")
            } else {
                None
            };
            LineageNode {
                catalog: f.dataset.catalog.clone(),
                schema: f.dataset.schema.clone(),
                table: f.dataset.table.clone(),
                field: f.field.clone(),
                kind,
                mask,
            }
        })
        .collect();

    let product_views = product_refs
        .iter()
        .map(|(dref, p)| ProductSummary {
            name: p.name.clone(),
            catalog: dref.catalog.clone(),
            schema: dref.schema.clone(),
            sql: p.sql.clone(),
            // A product that failed boot-time planning contributed no
            // nodes — surface that instead of showing a silently
            // absent product.
            planned: nodes.iter().any(|f| f.dataset == *dref),
        })
        .collect();

    LineageSnapshot {
        products: product_views,
        nodes: node_views,
        edges: edges
            .into_iter()
            .map(|(from, to, transform)| LineageEdgeView {
                from,
                to,
                transform,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use datafusion::common::TableReference;
    use datafusion::logical_expr::lit;
    use dataglot_core::lineage::{
        ColumnLineage, DatasetRef, InputFieldContribution, OutputFieldLineage, TransformationType,
    };

    fn dref(catalog: &str, table: &str) -> DatasetRef {
        DatasetRef {
            catalog: catalog.into(),
            schema: "public".into(),
            table: table.into(),
        }
    }

    fn contribution(
        output: &str,
        src: &DatasetRef,
        src_field: &str,
        transform: TransformationType,
    ) -> OutputFieldLineage {
        OutputFieldLineage {
            output_field: output.into(),
            inputs: vec![InputFieldContribution {
                field: FieldRef {
                    dataset: src.clone(),
                    field: src_field.into(),
                },
                transform,
                masking: false,
            }],
        }
    }

    fn product_cfg(name: &str, catalog: &str) -> DerivedProductConfig {
        DerivedProductConfig {
            name: name.into(),
            sql: format!("SELECT email FROM {catalog}.public.users"),
            catalog: Some(catalog.into()),
            schema: Some("public".into()),
            backing: crate::config::MaterializationBacking::default(),
            materialization: None,
        }
    }

    /// The snapshot mirrors the propagation the rule store performs:
    /// identity descendants of a configured mask are annotated
    /// `propagated`, aggregation outputs are not, and the source
    /// column itself is `configured`.
    #[test]
    fn snapshot_annotates_masks_like_the_enforcer() {
        let users = dref("pg", "users");
        let product = dref("pg", "v_emails");

        let mut graph = LineageGraph::new();
        graph.add_product(
            &product,
            &ColumnLineage {
                fields: vec![
                    contribution("email", &users, "email", TransformationType::Identity),
                    contribution("n", &users, "email", TransformationType::Aggregation),
                ],
            },
        );

        let configured = vec![ColumnMask {
            table: TableReference::bare("users"),
            column: "email".into(),
            mask: lit("***"),
            org: None,
            groups: None,
        }];

        let snap = build_lineage_snapshot(
            &graph,
            &[product_cfg("v_emails", "pg")],
            &configured,
            "pg",
            "public",
        );

        assert_eq!(snap.products.len(), 1);
        assert!(snap.products[0].planned);
        assert_eq!(snap.edges.len(), 2);

        let find = |table: &str, field: &str| {
            snap.nodes
                .iter()
                .find(|n| n.table == table && n.field == field)
                .unwrap_or_else(|| panic!("node {table}.{field} missing"))
        };
        let src = find("users", "email");
        assert_eq!((src.kind, src.mask), ("source", Some("configured")));
        let derived = find("v_emails", "email");
        assert_eq!(
            (derived.kind, derived.mask),
            ("derived", Some("propagated"))
        );
        // Aggregation breaks the chain — `n` stays unmasked.
        assert_eq!(find("v_emails", "n").mask, None);

        // Serializes to the wire shape the testbench consumes.
        let json = serde_json::to_value(&snap).expect("serializes");
        assert!(json["nodes"].as_array().unwrap().len() >= 3);
        assert!(json["edges"][0]["transform"].is_string());
    }

    /// A product that never planned (contributed no graph nodes) is
    /// reported `planned: false` rather than silently absent.
    #[test]
    fn unplanned_product_is_reported() {
        let snap = build_lineage_snapshot(
            &LineageGraph::new(),
            &[product_cfg("v_broken", "pg")],
            &[],
            "pg",
            "public",
        );
        assert_eq!(snap.products.len(), 1);
        assert!(!snap.products[0].planned);
        assert!(snap.nodes.is_empty() && snap.edges.is_empty());
    }
}
