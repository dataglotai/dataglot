-- TPC-H Query 13: Customer Distribution Query
-- LEFT OUTER JOIN + COUNT-of-non-NULL + double GROUP BY. The outer
-- query groups by c_count which is itself the COUNT in the inner
-- subquery — exercises grouping over a grouped column from a
-- subquery. The LEFT JOIN's negative WHERE on o_comment (NOT LIKE)
-- ensures the outer side carries customers with no orders.
SELECT
    c_count,
    COUNT(*) AS custdist
FROM (
    SELECT
        c_custkey,
        COUNT(o_orderkey) AS c_count
    FROM
        customer LEFT OUTER JOIN orders
            ON c_custkey = o_custkey
            AND o_comment NOT LIKE '%special%requests%'
    GROUP BY
        c_custkey
) AS c_orders
GROUP BY
    c_count
ORDER BY
    custdist DESC,
    c_count DESC;
