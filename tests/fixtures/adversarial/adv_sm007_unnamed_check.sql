-- Adversarial Fixture: Unnamed unstaged CHECK constraint
-- Risky migration: MUST NOT pass silently with exit code 0!
-- Either trigger SM007 (without NOT VALID) or fail closed with Exit Code 2 (unsupported syntax)
ALTER TABLE users ADD CHECK (phone_number IS NOT NULL);
