-- Semantic Near-Miss: Altering defaults or renaming columns without altering type
ALTER TABLE orders ALTER COLUMN status SET DEFAULT 'pending';
ALTER TABLE orders ALTER COLUMN status DROP DEFAULT;
ALTER TABLE orders RENAME COLUMN status TO order_status;
