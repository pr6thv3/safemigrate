-- Semantic Near-Miss: 3-step staged NOT NULL validation pattern
ALTER TABLE users ADD CONSTRAINT chk_users_phone_not_null CHECK (phone_number IS NOT NULL) NOT VALID;
ALTER TABLE users VALIDATE CONSTRAINT chk_users_phone_not_null;
ALTER TABLE users ALTER COLUMN phone_number SET NOT NULL;
