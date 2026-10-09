# Issue: Standardized Policy Enforcement and Exit Codes

## Description
Implement policy evaluation against rule severities and map findings to standardized CI exit codes.

## Acceptance Criteria
- [ ] Standardized exit codes:
  - `0`: Scan completed; no finding crossed the configured threshold.
  - `1`: Scan completed; policy threshold crossed (e.g., `--fail-on high`).
  - `2`: Invalid arguments, configuration, input, or unanalyzable syntax/parse failure.
  - `3`: Unexpected internal runtime exception.
- [ ] Precedence rule: When parse errors and policy findings coexist, exit with code 2 (fail closed).
- [ ] Severity ordering strictly enforced: `critical > high > medium > low > info`.
- [ ] Tests assert all exit codes across CLI edge cases.
