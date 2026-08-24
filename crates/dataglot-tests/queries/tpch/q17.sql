-- TPC-H Query 17: Small-Quantity-Order Revenue Query
-- Two-table join with a correlated AVG subquery in the WHERE
-- clause. The inner SELECT depends on the outer `p_partkey` —
-- DataFusion has to recognize the correlation and rewrite as a
-- join, otherwise the query degenerates to row-by-row execution.
-- Historical correlated-subquery risk shape, second to q21.
SELECT
    SUM(l_extendedprice) / 7.0 AS avg_yearly
FROM
    lineitem,
    part
WHERE
    p_partkey = l_partkey
    AND p_brand = 'Brand#23'
    AND p_container = 'MED BOX'
    AND l_quantity < (
        SELECT
            0.2 * AVG(l_quantity)
        FROM
            lineitem
        WHERE
            l_partkey = p_partkey
    );
