-- Semantic Near-Miss: Concurrent index creation
CREATE INDEX CONCURRENTLY idx_orders_customer ON orders (customer_id);
CREATE UNIQUE INDEX CONCURRENTLY idx_users_email ON users (email);
