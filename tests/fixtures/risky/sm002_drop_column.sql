-- Risky: Dropping columns
ALTER TABLE products DROP COLUMN description;
ALTER TABLE orders DROP COLUMN IF EXISTS internal_notes CASCADE;
