-- Risky: Explicit transaction block wrapping CONCURRENTLY
BEGIN;
CREATE INDEX CONCURRENTLY idx_orders_created ON orders (created_at);
COMMIT;
