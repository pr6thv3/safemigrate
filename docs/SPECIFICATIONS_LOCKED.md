# SafeMigrate — Locked Engineering Specifications & Baseline

**Status:** Locked Engineering Baseline  
**Sign-off Date:** 2026-10-09  
**Specification Origin:** Documents 05, 06, 08 (`/home/pr6thv3/Documents/flashcart_safemigrate_spec_pack`)

## 1. Locked Tooling & Core Architecture

- **Runtime & Dependencies:** Python 3.12+, SQLGlot (`dialect="postgres"`), Typer for CLI parsing, Rich for terminal rendering, Pydantic for schema validation.
- **AST Engine:** SQLGlot AST traversal is authoritative. Regex/string matching is forbidden for primary rule detection.
- **Pure Static Analysis:** No database connection required for core scanning. Read-only introspection is strictly opt-in and never mutates state.
- **Output Schemas:** Deterministic JSON schema v1.0 and SARIF 2.1.0 formatted for GitHub Code Scanning compatibility.
- **Exit Codes:**
  - `0`: Scan completed; no finding violated the configured policy threshold.
  - `1`: Scan completed; policy threshold crossed (e.g., `--fail-on high`).
  - `2`: Parse failure, invalid input, or unanalyzable dynamic SQL syntax.
  - `3`: Unexpected internal error.

## 2. Evidence Milestones (Document 08)

1. **Demonstration 3:** Scan intentionally risky FlashCart migration (`drop_description.sql`), outputting rule ID, severity, confidence, SARIF/JSON report, and CI exit code 1.
2. **Demonstration 4:** Pinned CI integration: PR containing risky migration fails CI gate; PR containing compatible additive migration (`add_vendor_note.sql`) passes CI gate.
