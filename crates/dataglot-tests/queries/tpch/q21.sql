-- TPC-H Query 21: Suppliers Who Kept Orders Waiting Query
-- The historical risk shape for DataFusion's planner — four-way join
-- (supplier × lineitem × orders × nation) with TWO correlated
-- subqueries against the same `lineitem` table: one EXISTS (any
-- supplier other than self on this order), one NOT EXISTS (no
-- supplier other than self has a later receipt). The combination
-- of correlated EXISTS + correlated NOT EXISTS over the same
-- alias group is what previously broke planning. Slice-3 spec
-- 03 flagged this as the risk-probe; q17 ran cleanly in batch 4
-- which was the positive signal.
SELECT
    s_name,
    COUNT(*) AS numwait
FROM
    supplier,
    lineitem l1,
    orders,
    nation
WHERE
    s_suppkey = l1.l_suppkey
    AND o_orderkey = l1.l_orderkey
    AND o_orderstatus = 'F'
    AND l1.l_receiptdate > l1.l_commitdate
    AND EXISTS (
        SELECT
            *
        FROM
            lineitem l2
        WHERE
            l2.l_orderkey = l1.l_orderkey
            AND l2.l_suppkey <> l1.l_suppkey
    )
    AND NOT EXISTS (
        SELECT
            *
        FROM
            lineitem l3
        WHERE
            l3.l_orderkey = l1.l_orderkey
            AND l3.l_suppkey <> l1.l_suppkey
            AND l3.l_receiptdate > l3.l_commitdate
    )
    AND s_nationkey = n_nationkey
    AND n_name = 'SAUDI ARABIA'
GROUP BY
    s_name
ORDER BY
    numwait DESC,
    s_name
LIMIT 100;
