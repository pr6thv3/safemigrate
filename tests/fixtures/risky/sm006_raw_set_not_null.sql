-- Risky: SET NOT NULL without staged validation, and ADD NOT NULL without default
ALTER TABLE users ALTER COLUMN phone_number SET NOT NULL;
ALTER TABLE orders ADD COLUMN tracking_code VARCHAR(100) NOT NULL;
