-- Adversarial Fixture: Unstaged Foreign Key with comment containing NOT VALID
-- Risky migration: MUST trigger SM007 (Medium)
ALTER TABLE orders ADD CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users(id) /* NOT VALID */;
