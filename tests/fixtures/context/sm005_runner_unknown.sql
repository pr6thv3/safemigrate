-- Context: Runner mode unknown
CREATE INDEX CONCURRENTLY idx_orders_created ON orders (created_at);
