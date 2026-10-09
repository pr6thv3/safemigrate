-- Semantic Near-Miss: Adding columns or dropping constraints
ALTER TABLE products ADD COLUMN description TEXT;
ALTER TABLE products DROP CONSTRAINT fk_products_vendor;
ALTER TABLE orders DROP CONSTRAINT check_positive_total;
