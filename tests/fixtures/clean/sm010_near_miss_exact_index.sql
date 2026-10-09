-- Semantic Near-Miss: Supporting exact index exists on foreign key column
CREATE TABLE parent_vendors (
    id UUID PRIMARY KEY
);
CREATE TABLE child_products (
    id UUID PRIMARY KEY,
    vendor_id UUID NOT NULL REFERENCES parent_vendors(id),
    name TEXT NOT NULL
);
CREATE INDEX idx_child_products_vendor ON child_products (vendor_id);
