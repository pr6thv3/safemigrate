-- Semantic Near-Miss: Dropping views, sequences, or creating tables is NOT a table drop
DROP VIEW active_users_view;
DROP MATERIALIZED VIEW IF EXISTS monthly_sales_summary;
DROP SEQUENCE user_id_sequence;
CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(100));
TRUNCATE TABLE staging_events;
