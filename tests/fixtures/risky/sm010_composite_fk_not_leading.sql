-- Risky: Composite index exists, but FK column is NOT the leading column
CREATE TABLE child_orders (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_child_orders_created_user ON child_orders (created_at, user_id);
