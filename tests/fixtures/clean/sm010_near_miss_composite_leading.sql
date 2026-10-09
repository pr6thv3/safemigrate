-- Semantic Near-Miss: Composite index where FK column is the LEADING column
CREATE TABLE child_orders (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_child_orders_user_created ON child_orders (user_id, created_at);
