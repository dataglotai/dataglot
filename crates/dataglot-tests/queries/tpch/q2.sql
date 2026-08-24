-- TPC-H Query 2: Minimum Cost Supplier Query
-- Nested correlated subquery picking the lowest-cost supplier per part
-- in a region. Five-way outer join + inner correlated 4-way join. The
-- correlated MIN(ps_supplycost) is the interesting bit — DataFusion's
-- planner has to recognize the equality predicate as a join condition,
-- not a per-row aggregate. Not in the headline geomean (the correlated
-- subquery shape is its own benchmark axis).
SELECT
    s_acctbal,
    s_name,
    n_name,
    p_partkey,
    p_mfgr,
    s_address,
    s_phone,
    s_comment
FROM
    part,
    supplier,
    partsupp,
    nation,
    region
WHERE
    p_partkey = ps_partkey
    AND s_suppkey = ps_suppkey
    AND p_size = 15
    AND p_type LIKE '%BRASS'
    AND s_nationkey = n_nationkey
    AND n_regionkey = r_regionkey
    AND r_name = 'EUROPE'
    AND ps_supplycost = (
        SELECT
            MIN(ps_supplycost)
        FROM
            partsupp,
            supplier,
            nation,
            region
        WHERE
            p_partkey = ps_partkey
            AND s_suppkey = ps_suppkey
            AND s_nationkey = n_nationkey
            AND n_regionkey = r_regionkey
            AND r_name = 'EUROPE'
    )
ORDER BY
    s_acctbal DESC,
    n_name,
    s_name,
    p_partkey
LIMIT 100;
