-- Context: Isolated migration file without preceding table creation history
ALTER TABLE child_orders ADD CONSTRAINT fk_child_orders_user FOREIGN KEY (user_id) REFERENCES users(id) NOT VALID;
