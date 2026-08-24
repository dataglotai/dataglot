-- TPC-H Query 1: Pricing Summary Report Query
-- Single-table aggregation over `lineitem`. Harness validation:
-- proves the seed parquet file + table registration + GROUP BY + ORDER BY
-- round-trip through the `SessionContext`. Not a join workload, so not
-- in the headline geomean.
SELECT
    l_returnflag,
    l_linestatus,
    SUM(l_quantity)                                          AS sum_qty,
    SUM(l_extendedprice)                                     AS sum_base_price,
    SUM(l_extendedprice * (1 - l_discount))                  AS sum_disc_price,
    SUM(l_extendedprice * (1 - l_discount) * (1 + l_tax))    AS sum_charge,
    AVG(l_quantity)                                          AS avg_qty,
    AVG(l_extendedprice)                                     AS avg_price,
    AVG(l_discount)                                          AS avg_disc,
    COUNT(*)                                                 AS count_order
FROM
    lineitem
WHERE
    l_shipdate <= DATE '1998-12-01' - INTERVAL '90' DAY
GROUP BY
    l_returnflag,
    l_linestatus
ORDER BY
    l_returnflag,
    l_linestatus;
