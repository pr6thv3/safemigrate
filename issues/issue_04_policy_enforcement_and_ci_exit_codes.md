# Issue: Configurable Policy Enforcement and Exit Codes

## Description
Implement policy evaluation against rule severities and map findings to deterministic CI exit codes.

## Acceptance Criteria
- [ ] Threshold flag `--fail-on [critical|high|medium|low]` controls process termination.
- [ ] Exit code `0` when all findings are below the configured threshold.
- [ ] Exit code `1` when any finding meets or exceeds the threshold.
- [ ] Exit code `2` for syntax parse errors or unanalyzable inputs.
- [ ] Exit code `3` for unexpected runtime exceptions.
