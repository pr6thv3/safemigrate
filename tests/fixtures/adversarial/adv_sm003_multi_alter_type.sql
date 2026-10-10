-- Adversarial Fixture: Multi-action ALTER TABLE changing column types
-- Risky migration: MUST NOT pass silently with exit code 0!
-- Either trigger SM003 for the column type changes or fail closed with Exit Code 2 (unsupported syntax)
ALTER TABLE products ALTER COLUMN description TYPE text, ALTER COLUMN status TYPE varchar(50);
