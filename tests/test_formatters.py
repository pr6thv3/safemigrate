"""Tests for JSON v1.0 and OASIS SARIF 2.1.0 formatters."""

import json
from pathlib import Path
import jsonschema
import pytest

from safemigrate.analyzer import MigrationAnalyzer
from safemigrate.formatters.json import format_json
from safemigrate.formatters.sarif import format_sarif
from safemigrate.models import Severity


# Minimal JSON Schema v1.0 specification for SafeMigrate
JSON_REPORT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": [
        "schema_version",
        "tool",
        "target_engine",
        "pg_version",
        "migration_transaction_mode",
        "scanned_files",
        "diagnostics",
        "findings",
        "summary",
        "policy",
    ],
    "properties": {
        "schema_version": {"type": "string", "const": "1.0"},
        "tool": {
            "type": "object",
            "required": ["name", "version"],
            "properties": {
                "name": {"type": "string"},
                "version": {"type": "string"},
            },
        },
        "target_engine": {"type": "string"},
        "pg_version": {"type": "integer"},
        "migration_transaction_mode": {"type": "string"},
        "scanned_files": {"type": "array", "items": {"type": "string"}},
        "diagnostics": {"type": "array"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "rule_id",
                    "rule_title",
                    "rule_version",
                    "severity",
                    "confidence",
                    "file",
                    "line",
                    "column",
                    "statement",
                    "affected_object",
                    "evidence",
                    "explanation",
                    "recommendation",
                ],
            },
        },
        "summary": {
            "type": "object",
            "required": [
                "total_files",
                "total_statements",
                "total_findings",
                "severities",
                "parse_errors",
            ],
        },
        "policy": {
            "type": "object",
            "required": ["fail_on", "passed", "exit_code"],
        },
    },
}


def test_json_formatter_structure_and_schema_validation(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer(deterministic=True)
    report = analyzer.scan_path(risky_fixtures_dir / "drop_description.sql")
    json_str = format_json(report)
    data = json.loads(json_str)

    # Validate against JSON Schema
    jsonschema.validate(instance=data, schema=JSON_REPORT_SCHEMA)

    assert data["schema_version"] == "1.0"
    assert data["tool"]["name"] == "safemigrate"
    assert data["tool"]["version"] == "0.1.0"
    assert data["scan_timestamp"] is None  # Deterministic mode
    assert len(data["findings"]) == 1
    finding = data["findings"][0]
    assert finding["rule_id"] == "SM002"
    assert finding["severity"] == "high"
    assert finding["affected_object"]["table"] == "products"
    assert finding["affected_object"]["column"] == "description"


def test_json_formatter_determinism(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer(deterministic=True)
    report1 = analyzer.scan_path(risky_fixtures_dir / "drop_description.sql")
    report2 = analyzer.scan_path(risky_fixtures_dir / "drop_description.sql")

    json1 = format_json(report1)
    json2 = format_json(report2)
    assert json1 == json2


def test_sarif_formatter_structure(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer(deterministic=True)
    report = analyzer.scan_path(risky_fixtures_dir / "drop_description.sql")
    sarif_str = format_sarif(report)
    sarif = json.loads(sarif_str)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]

    # Driver
    assert run["tool"]["driver"]["name"] == "safemigrate"
    assert run["tool"]["driver"]["version"] == "0.1.0"
    assert len(run["tool"]["driver"]["rules"]) >= 8

    # Results
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "SM002"
    assert res["level"] == "error"  # high maps to error
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    assert res["properties"]["confidence"] == "high"
    assert res["properties"]["severity"] == "high"
    assert res["properties"]["affectedObject"]["table"] == "products"
