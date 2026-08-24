-- TPC-H Query 16: Parts/Supplier Relationship Query
-- Anti-join via NOT IN against a subquery selecting suppliers with
-- complaint comments. Three-table join (partsupp × part) + the
-- NOT IN suppkey filter + a COUNT(DISTINCT) aggregate. Tests
-- DataFusion's anti-join rewrite for NOT IN with a non-correlated
-- subquery.
SELECT
    p_brand,
    p_type,
    p_size,
    COUNT(DISTINCT ps_suppkey) AS supplier_cnt
FROM
    partsupp,
    part
WHERE
    p_partkey = ps_partkey
    AND p_brand <> 'Brand#45'
    AND p_type NOT LIKE 'MEDIUM POLISHED%'
    AND p_size IN (49, 14, 23, 45, 19, 3, 36, 9)
    AND ps_suppkey NOT IN (
        SELECT
            s_suppkey
        FROM
            supplier
        WHERE
            s_comment LIKE '%Customer%Complaints%'
    )
GROUP BY
    p_brand,
    p_type,
    p_size
ORDER BY
    supplier_cnt DESC,
    p_brand,
    p_type,
    p_size;
