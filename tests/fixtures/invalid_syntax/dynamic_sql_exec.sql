-- Dynamic SQL execution
DO $$
BEGIN
    EXECUTE format('DROP TABLE %I', 'users');
END $$;
