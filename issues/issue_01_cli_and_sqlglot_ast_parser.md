# Issue: SafeMigrate CLI and SQLGlot AST Parser Pipeline

## Description
Establish the Python package and Typer CLI pipeline parsing PostgreSQL DDL into SQLGlot AST nodes.

## Acceptance Criteria
- [ ] Command `safemigrate scan <path>` accepts files and directories.
- [ ] Parses PostgreSQL dialect DDL using `sqlglot.parse(..., read="postgres")`.
- [ ] Handles unparseable or dynamic SQL cleanly with exit code 2 and helpful file/line diagnostics.
- [ ] CLI flags: `--format [text|json|sarif]`, `--output <file>`, `--fail-on [critical|high|medium|low]`, `--pg-version`.
