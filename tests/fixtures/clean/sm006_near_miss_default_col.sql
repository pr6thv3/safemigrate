-- Semantic Near-Miss: Adding column with default or inside CREATE TABLE
ALTER TABLE users ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT false;
CREATE TABLE notification_tokens (
    id UUID PRIMARY KEY,
    token TEXT NOT NULL
);
