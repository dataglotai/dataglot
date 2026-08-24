-- TPC-H Query 20: Potential Part Promotion Query
-- Two-level IN-subquery pattern. The outer SELECT finds suppliers in
-- Canada whose suppkey is in the inner subquery (matched part
-- excess), which itself uses a correlated subquery to compare
-- partsupp.availqty against an aggregate of lineitem ship-quantity.
-- Stresses both the IN-subquery semi-join rewrite (outer level) AND
-- the correlated-aggregate rewrite (inner level) at the same time.
SELECT
    s_name,
    s_address
FROM
    supplier,
    nation
WHERE
    s_suppkey IN (
        SELECT
            ps_suppkey
        FROM
            partsupp
        WHERE
            ps_partkey IN (
                SELECT
                    p_partkey
                FROM
                    part
                WHERE
                    p_name LIKE 'forest%'
            )
            AND ps_availqty > (
                SELECT
                    0.5 * SUM(l_quantity)
                FROM
                    lineitem
                WHERE
                    l_partkey = ps_partkey
                    AND l_suppkey = ps_suppkey
                    AND l_shipdate >= DATE '1994-01-01'
                    AND l_shipdate < DATE '1994-01-01' + INTERVAL '1' YEAR
            )
    )
    AND s_nationkey = n_nationkey
    AND n_name = 'CANADA'
ORDER BY
    s_name;
