-- TPC-H Query 6: Forecasting Revenue Change Query
-- Single-table predicate sweep over `lineitem`. Cheapest of the 22 —
-- harness sanity check that the lineitem table parquet file is wired
-- and indexed correctly. Not in the headline geomean.
SELECT
    SUM(l_extendedprice * l_discount) AS revenue
FROM
    lineitem
WHERE
    l_shipdate >= DATE '1994-01-01'
    AND l_shipdate < DATE '1994-01-01' + INTERVAL '1' YEAR
    AND l_discount BETWEEN 0.06 - 0.01 AND 0.06 + 0.01
    AND l_quantity < 24;
