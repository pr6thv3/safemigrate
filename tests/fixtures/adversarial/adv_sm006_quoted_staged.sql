-- Adversarial Fixture: Staged NOT NULL with quoted identifier
-- Safe near-miss: Should NOT trigger SM006
ALTER TABLE "users" ADD CONSTRAINT "chk_users_phone" CHECK ("phone_number" IS NOT NULL) NOT VALID;
ALTER TABLE "users" VALIDATE CONSTRAINT "chk_users_phone";
ALTER TABLE "users" ALTER COLUMN "phone_number" SET NOT NULL;
