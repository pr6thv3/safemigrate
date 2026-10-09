-- Risky: Non-concurrent index creation
CREATE INDEX idx_orders_customer ON orders (customer_id);
