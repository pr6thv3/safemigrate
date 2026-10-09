-- Semantic Near-Miss: Concurrent index run with --migration-transaction-mode not_wrapped
CREATE INDEX CONCURRENTLY idx_orders_created ON orders (created_at);
