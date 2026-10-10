-- Adversarial Fixture: Obfuscated Dynamic SQL execution
-- Must fail closed with Exit Code 2
DO $$
BEGIN
    EXECUTE   format('DROP TABLE %I', 'users');
END $$;
