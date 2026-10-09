# Issue: Evidence Demonstration 3 — Risky Migration Detection

## Description
Execute and document Demonstration 3 from Document 08 scanning an intentionally risky FlashCart migration.

## Acceptance Criteria
- [ ] Fixture `drop_description.sql` containing `ALTER TABLE products DROP COLUMN description;`.
- [ ] SafeMigrate CLI scans the fixture and outputs finding: Rule `SM002`, Severity `High`, Confidence `High`.
- [ ] Generates valid JSON and SARIF artifacts containing rule rationale and mitigation advice.
- [ ] Exits with code `1` when evaluated with `--fail-on high`.
- [ ] Captures raw commands, version, JSON report, and execution log.
