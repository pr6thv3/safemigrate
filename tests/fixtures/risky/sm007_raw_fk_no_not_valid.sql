-- Risky: ADD CONSTRAINT without NOT VALID
ALTER TABLE orders ADD CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users(id);
ALTER TABLE products ADD CONSTRAINT chk_price_positive CHECK (price > 0);
