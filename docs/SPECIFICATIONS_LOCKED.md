# SafeMigrate — Locked Engineering Specifications & Baseline

**Status:** Locked Engineering Baseline (Fully Approved)  
**Sign-off Date:** 2026-10-09  
**Specification Origin:** Documents 05, 06, 08 + `REVIEW_DECISIONS.md`

## 1. Locked Tooling & Core Architecture

- **Runtime & Dependencies:** Python 3.12+, SQLGlot (`dialect="postgres"`), Typer for CLI parsing, Rich for terminal rendering, Pydantic for schema validation.
- **AST Engine & Lenient Parser Guardrails:** SQLGlot AST traversal is authoritative for static structure. Since SQLGlot is intentionally lenient, SafeMigrate makes no claim of runtime SQL engine validity; real syntax and migration runner compatibility are verified via PostgreSQL integration tests on disposable containers.
- **Transaction-Aware Runner Context:** Configurable `migration_transaction_mode = wrapped | not_wrapped | unknown` via CLI flag `--migration-transaction-mode` and config file. Rule `SM005` uses this context to detect `CREATE INDEX CONCURRENTLY` inside transaction blocks.
- **Pure Static Analysis:** No database connection required for core scanning. Read-only schema introspection is strictly opt-in and never mutates state.
- **Output Schemas:** Deterministic JSON schema v1.0 (volatile timestamps omitted or normalized in deterministic fixtures) and SARIF 2.1.0 formatted for GitHub Code Scanning compatibility.
- **Standardized Exit Codes:**
  - `0`: Scan completed; no finding crossed the configured `--fail-on` threshold.
  - `1`: Scan completed; policy threshold crossed (e.g., `--fail-on high`).
  - `2`: Invalid arguments, configuration, input, unanalyzable dynamic SQL, or parse failure.
  - `3`: Unexpected internal runtime failure.

## 2. Rule Catalogue Release Scope

### First Usable Release Rules
- `SM001` — `DROP TABLE` (Severity: High/Critical, Confidence: High)
- `SM002` — `DROP COLUMN` (Severity: High, Confidence: High)
- `SM003` — `ALTER COLUMN TYPE` (Severity: High/Medium, Confidence: Medium/High; version and operation sensitive)
- `SM004` — `CREATE INDEX` without `CONCURRENTLY` (Severity: Medium, Confidence: High; potential write lockouts)
- `SM005` — `CREATE INDEX CONCURRENTLY` inside transaction block (Severity: High, Confidence: High; evaluated against `migration_transaction_mode`)
- `SM006` — Add `NOT NULL` or constraint without staged validation (Severity: Medium, Confidence: High)
- `SM007` — Add foreign-key or CHECK constraint without staged validation (`NOT VALID` then `VALIDATE CONSTRAINT`)
- `SM010` — Unindexed foreign key referencing columns (Severity: Medium, Confidence: Medium; only when complete schema context or migration sequence is available; reports `insufficient_context` when unknown)

### Post-1.0 Roadmap Heuristics
- `SM008` — Broad `UPDATE`/`DELETE` heuristic without bounded batching.
- `SM009` — Immediate rename/drop breaking rolling deployment compatibility.

## 3. Evidence Milestones (Document 08)

1. **Demonstration 3:** Scan intentionally risky FlashCart migration (`drop_description.sql`), outputting rule ID `SM002`, severity `high`, confidence `high`, SARIF/JSON report, and CI exit code 1.
2. **Demonstration 4:** Pinned CI integration: PR containing risky migration fails CI gate; PR containing compatible additive migration (`add_vendor_note.sql`) passes CI gate; raw outputs, commit SHAs, and reports preserved.
