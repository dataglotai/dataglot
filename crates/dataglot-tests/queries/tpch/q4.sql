-- TPC-H Query 4: Order Priority Checking Query
-- Semijoin via EXISTS on lineitem from orders. Tests the planner's
-- ability to rewrite EXISTS into a semi-join rather than a left-join
-- with NULL filter. Two-table query, but the EXISTS rewrite is what
-- makes it interesting. Not in the headline geomean.
SELECT
    o_orderpriority,
    COUNT(*) AS order_count
FROM
    orders
WHERE
    o_orderdate >= DATE '1993-07-01'
    AND o_orderdate < DATE '1993-07-01' + INTERVAL '3' MONTH
    AND EXISTS (
        SELECT
            *
        FROM
            lineitem
        WHERE
            l_orderkey = o_orderkey
            AND l_commitdate < l_receiptdate
    )
GROUP BY
    o_orderpriority
ORDER BY
    o_orderpriority;
