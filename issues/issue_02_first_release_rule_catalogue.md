# Issue: First-Release Rule Catalogue (SM001–SM007 and SM010)

## Description
Implement the complete first-release rule set covering destructive changes, lockouts, transaction block violations, and unindexed foreign keys. Clearly separate these from post-1.0 heuristics (SM008, SM009).

## Acceptance Criteria
- [ ] `SM001`: Detects `DROP TABLE` (Severity: High/Critical, Confidence: High).
- [ ] `SM002`: Detects `DROP COLUMN` (Severity: High, Confidence: High).
- [ ] `SM003`: Detects `ALTER COLUMN TYPE` with version/type-specific lock advice.
- [ ] `SM004`: Detects `CREATE INDEX` without `CONCURRENTLY` (Severity: Medium, Confidence: High).
- [ ] `SM005`: Detects `CREATE INDEX CONCURRENTLY` when runner wraps transactions (`migration_transaction_mode = wrapped`).
- [ ] `SM006`: Detects `NOT NULL` or constraint addition without staged validation.
- [ ] `SM007`: Detects foreign-key / check constraints without staged validation (`NOT VALID` then `VALIDATE CONSTRAINT`).
- [ ] `SM010`: Detects unindexed foreign-key referencing columns when full migration/schema context is available; outputs `insufficient_context` when context is missing.
- [ ] Heuristics `SM008` (broad UPDATE/DELETE) and `SM009` (rolling deploy renames) are formally documented as post-1.0 roadmap items.
- [ ] Positive, negative (near-miss), and missing-context test fixtures implemented for every rule.
