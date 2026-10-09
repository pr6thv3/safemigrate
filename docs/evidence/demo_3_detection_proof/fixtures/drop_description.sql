-- Demonstration 3 Fixture: Intentionally Risky Migration
-- Dropping active column 'description' from FlashCart 'products' table
ALTER TABLE products DROP COLUMN description;
