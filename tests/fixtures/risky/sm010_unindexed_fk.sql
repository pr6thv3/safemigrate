-- Risky: Foreign key on child table with no index covering referencing column
CREATE TABLE parent_vendors (
    id UUID PRIMARY KEY
);
CREATE TABLE child_products (
    id UUID PRIMARY KEY,
    vendor_id UUID NOT NULL REFERENCES parent_vendors(id),
    name TEXT NOT NULL
);
