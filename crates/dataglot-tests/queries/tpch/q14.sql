-- TPC-H Query 14: Promotion Effect Query
-- Two-table join with a single CASE aggregator weighted by promo
-- price share. Lightweight cardinality-wise but the percentage
-- computation (100 × promo_revenue / total_revenue) tests the
-- planner's handling of nested aggregates inside arithmetic.
SELECT
    100.00 * SUM(
        CASE WHEN p_type LIKE 'PROMO%'
             THEN l_extendedprice * (1 - l_discount)
             ELSE 0
        END
    ) / SUM(l_extendedprice * (1 - l_discount)) AS promo_revenue
FROM
    lineitem,
    part
WHERE
    l_partkey = p_partkey
    AND l_shipdate >= DATE '1995-09-01'
    AND l_shipdate < DATE '1995-09-01' + INTERVAL '1' MONTH;
