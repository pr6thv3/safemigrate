"""OASIS SARIF 2.1.0 Formatter for SafeMigrate GitHub Code Scanning Integration."""

import json
from typing import Any, Dict, List

from safemigrate.models import Finding, ScanReport, Severity
from safemigrate.rules import ACTIVE_RULES


def _map_severity_to_sarif_level(severity: Severity) -> str:
    """Maps SafeMigrate severity to SARIF 2.1.0 level."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    elif severity == Severity.MEDIUM:
        return "warning"
    else:
        return "note"


def format_sarif(report: ScanReport, indent: int = 2) -> str:
    """Formats a ScanReport into standard OASIS SARIF 2.1.0 JSON format."""
    # Build rules catalogue for SARIF driver
    sarif_rules: List[Dict[str, Any]] = []
    rule_index_map: Dict[str, int] = {}

    for idx, rule in enumerate(ACTIVE_RULES):
        rule_index_map[rule.rule_id] = idx
        sarif_rules.append(
            {
                "id": rule.rule_id,
                "name": rule.title.replace(" ", ""),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {
                    "text": rule.remediation,
                    "markdown": f"### Remediation\n{rule.remediation}\n\n**Hazard Rationale:** {rule.hazard_rationale}",
                },
                "defaultConfiguration": {
                    "level": _map_severity_to_sarif_level(rule.default_severity),
                },
                "properties": {
                    "precision": rule.confidence.value,
                    "tags": ["migration", "postgresql", "database-safety"],
                },
            }
        )

    # Build results
    sarif_results: List[Dict[str, Any]] = []
    for finding in report.findings:
        rule_idx = rule_index_map.get(finding.rule_id, 0)
        level = _map_severity_to_sarif_level(finding.severity)

        affected_dict = finding.affected_object.model_dump(by_alias=True, exclude_none=True)

        sarif_results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_idx,
                "level": level,
                "message": {
                    "text": f"{finding.rule_title}: {finding.explanation}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file,
                            },
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                                "snippet": {
                                    "text": finding.statement,
                                },
                            },
                        },
                    }
                ],
                "properties": {
                    "confidence": finding.confidence.value,
                    "severity": finding.severity.value,
                    "affectedObject": affected_dict,
                    "evidence": finding.evidence,
                    "recommendation": finding.recommendation,
                    "contextUsed": finding.context_used,
                    "contextNotKnown": finding.context_not_known,
                },
            }
        )

    sarif_doc: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "safemigrate",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/pr6thv3/safemigrate",
                        "rules": sarif_rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": report.policy.exit_code in (0, 1),
                        "exitCode": report.policy.exit_code,
                        "exitCodeDescription": (
                            "Analysis passed"
                            if report.policy.exit_code == 0
                            else (
                                "Policy threshold breached"
                                if report.policy.exit_code == 1
                                else "Parse/syntax failure"
                            )
                        ),
                    }
                ],
                "artifacts": [
                    {
                        "location": {
                            "uri": f,
                        },
                        "sourceLanguage": "sql",
                    }
                    for f in report.scanned_files
                ],
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=indent, sort_keys=True)
