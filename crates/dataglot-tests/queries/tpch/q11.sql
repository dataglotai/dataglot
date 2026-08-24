-- TPC-H Query 11: Important Stock Identification Query
-- HAVING subquery — the inner SELECT computes a scalar threshold
-- (0.0001 × total partsupp value for the nation) which the outer
-- HAVING filters against. Tests the planner's recognition of a
-- correlated scalar subquery that resolves to a constant per the
-- WHERE clause.
SELECT
    ps_partkey,
    SUM(ps_supplycost * ps_availqty) AS value
FROM
    partsupp,
    supplier,
    nation
WHERE
    ps_suppkey = s_suppkey
    AND s_nationkey = n_nationkey
    AND n_name = 'GERMANY'
GROUP BY
    ps_partkey
HAVING
    SUM(ps_supplycost * ps_availqty) > (
        SELECT
            SUM(ps_supplycost * ps_availqty) * 0.0001
        FROM
            partsupp,
            supplier,
            nation
        WHERE
            ps_suppkey = s_suppkey
            AND s_nationkey = n_nationkey
            AND n_name = 'GERMANY'
    )
ORDER BY
    value DESC;
