# SafeMigrate

An automated PostgreSQL schema migration risk analyzer that statically evaluates SQL migrations before execution, producing deterministic findings, rich terminal output, JSON reports, and SARIF 2.1.0 artifacts for CI/CD gates.

## Core Capabilities

- **AST-Aware Analysis**: Uses SQLGlot to parse PostgreSQL DDL into structured ASTs rather than relying on brittle regex/text matching.
- **Explainable Findings**: Every rule finding reports stable Rule ID, Severity, Confidence, Line/Column locations, Contextual Rationale, and Actionable Mitigation Guidance.
- **Zero Database Side Effects**: Operates purely on migration files statically by default. Does not execute DDL or modify database states.
- **CI & SARIF Integration**: Emits SARIF 2.1.0 compatible with GitHub Code Scanning, deterministic JSON for automation, and configurable `--fail-on` policy exit codes.

## Initial Rule Catalog

| Rule ID | Name | Severity | Description |
|---|---|---|---|
| `SM001` | Destructive Table Drop | High / Critical | Detects `DROP TABLE` operations risking irreversible data loss. |
| `SM002` | Destructive Column Drop | High | Detects `DROP COLUMN` breaking backward compatibility with active application versions. |
| `SM003` | Column Type Alteration | High / Medium | Detects `ALTER COLUMN TYPE` operations risking prolonged table rewrites and exclusive locks. |
| `SM004` | Non-Concurrent Index Creation | Medium | Detects `CREATE INDEX` without `CONCURRENTLY` causing write lockouts on high-traffic tables. |
| `SM005` | Transaction-Wrapped Concurrent Index | High | Detects `CREATE INDEX CONCURRENTLY` inside explicit transaction blocks that fail in PostgreSQL. |

## Demonstrations & Evidence (Document 08)

SafeMigrate powers two core empirical proofs:
- **Demonstration 3 (Risky Change Detection)**: Accurately scans an intentionally risky migration, outputting finding details and triggering CI failure under policy.
- **Demonstration 4 (PR Gate Integration)**: Evaluates FlashCart migration pull requests in GitHub Actions, blocking destructive changes while passing compatible additive migrations.
