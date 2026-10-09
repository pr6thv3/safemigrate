# Issue: Initial Rule Catalogue (SM001 through SM005)

## Description
Implement the core high-confidence rules detecting destructive DDL, table lockouts, and transaction wrapper conflicts.

## Acceptance Criteria
- [ ] `SM001`: Detects `DROP TABLE` (Severity: High, Confidence: High).
- [ ] `SM002`: Detects `DROP COLUMN` (Severity: High, Confidence: High).
- [ ] `SM003`: Detects `ALTER COLUMN TYPE` with version/type-specific lock advice.
- [ ] `SM004`: Detects `CREATE INDEX` without `CONCURRENTLY` (Severity: Medium, Confidence: High).
- [ ] `SM005`: Detects `CREATE INDEX CONCURRENTLY` inside explicit transaction blocks (Severity: High, Confidence: High).
- [ ] Positive and near-miss test fixtures implemented for every rule.
