# Issue: SafeMigrate CLI and SQLGlot AST Parser Pipeline

## Description
Establish the Python package and Typer CLI pipeline parsing PostgreSQL DDL into SQLGlot AST nodes, with transaction context support and syntax verification tests.

## Acceptance Criteria
- [ ] Command `safemigrate scan <path>` accepts files and directories.
- [ ] Parses PostgreSQL dialect DDL using `sqlglot.parse(..., read="postgres")`.
- [ ] Supports `--migration-transaction-mode [wrapped|not_wrapped|unknown]` (default: `unknown`).
- [ ] Unknown or dynamic SQL produces an explicit unsupported/uncertain diagnostic and exits with code 2.
- [ ] Lenient parser behavior is tested against real PostgreSQL grammar on a disposable container.
- [ ] CLI flags: `--format [text|json|sarif]`, `--output <file>`, `--fail-on [critical|high|medium|low]`, `--pg-version`.
