-- Risky when run with --migration-transaction-mode wrapped
CREATE INDEX CONCURRENTLY idx_orders_created ON orders (created_at);
