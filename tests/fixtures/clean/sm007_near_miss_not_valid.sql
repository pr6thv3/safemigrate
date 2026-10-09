-- Semantic Near-Miss: Staged constraint addition with NOT VALID
ALTER TABLE orders ADD CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users(id) NOT VALID;
ALTER TABLE products ADD CONSTRAINT chk_price_positive CHECK (price > 0) NOT VALID;
ALTER TABLE orders VALIDATE CONSTRAINT fk_orders_user;
CREATE TABLE vendor_payouts (
    id UUID PRIMARY KEY,
    vendor_id UUID NOT NULL REFERENCES vendors(id),
    amount_cents INT NOT NULL CHECK (amount_cents >= 0)
);
