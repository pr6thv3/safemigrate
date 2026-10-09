-- Risky: Column type alteration forcing table rewrite
ALTER TABLE orders ALTER COLUMN user_id TYPE BIGINT;
