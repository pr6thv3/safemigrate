# Issue: Evidence Demonstration 4 — CI PR Gate Integration

## Description
Execute and document Demonstration 4 from Document 08 proving that SafeMigrate protects pull requests in CI.

## Acceptance Criteria
- [ ] Pinned SafeMigrate version scanned in a simulated or live GitHub Actions pull request.
- [ ] PR containing risky migration receives expected failure and blocks merge.
- [ ] PR containing compatible additive migration (`add_vendor_note.sql`) passes configured policy gate.
- [ ] SARIF artifact uploaded to GitHub Actions summary.
