-- Seed the whole control plane over SQL — nothing lives in the config file.
-- Run as the bootstrap `admin` against the `dataglot` bootstrap database.
-- Expects demo sources on postgres :5433, postgres-orders :5434, mysql :3306
-- (maintainers bring these up with the dev repo's `make demo-sources`; any
-- Postgres/MySQL you already run works too — adjust the DSNs below).

-- Encrypted source credentials (need DATAGLOT_SECRET_KEY):
CREATE SECRET pg_dsn     AS 'host=127.0.0.1 port=5433 user=postgres password=postgres dbname=demo';
CREATE SECRET orders_dsn AS 'host=127.0.0.1 port=5434 user=postgres password=postgres dbname=demo';

-- Catalogs that reference the secrets (the DSN is never inlined):
CREATE CATALOG pg         WITH (kind = 'postgres', dsn_secret = 'pg_dsn');
CREATE CATALOG pg_orders  WITH (kind = 'postgres', dsn_secret = 'orders_dsn');
-- MySQL has no dsn_secret field yet, so inline (or use dsn_env):
CREATE CATALOG mysql_demo WITH (kind = 'mysql', dsn = 'mysql://demouser:demopass@127.0.0.1:3306/demo');

-- A derived product defined entirely over SQL — no dataglot.toml
-- [[derived_products]] entry needed (this was the F2 fileless gap). It
-- federates Postgres orders with the MySQL customer segments; it is a plain
-- (non-materialized) view, planned on each read, queryable like any table by
-- every subsequent connection, and it appears in lineage. A mask on an
-- underlying source column stays masked through it (the plan is inlined).
CREATE VIEW order_segments AS
  SELECT s.segment, o.amount, o.user_id
  FROM   pg_orders.public.orders o
  JOIN   mysql_demo.demo.customer_segments s ON s.user_id = o.user_id;

-- A runtime login — no config entry, authenticates via md5:
CREATE USER analyst WITH PASSWORD 'analyst-pw';
