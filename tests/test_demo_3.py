"""Tests verifying Demonstration 3: SafeMigrate Detection Proof."""

import json
from pathlib import Path
from typer.testing import CliRunner

from safemigrate.cli import app

runner = CliRunner()


def test_demonstration_3_detection_proof():
    demo_dir = Path(__file__).parent.parent / "docs" / "evidence" / "demo_3_detection_proof"
    fixture_path = demo_dir / "fixtures" / "drop_description.sql"

    assert fixture_path.exists(), "Demo 3 fixture must exist"

    # Run scan with --fail-on high
    result = runner.invoke(app, ["scan", str(fixture_path), "--fail-on", "high", "--format", "json"])

    # Must exit with code 1 (policy breach)
    assert result.exit_code == 1

    # Verify JSON output
    data = json.loads(result.stdout)
    assert data["policy"]["exit_code"] == 1
    assert data["policy"]["passed"] is False
    assert len(data["findings"]) == 1

    finding = data["findings"][0]
    assert finding["rule_id"] == "SM002"
    assert finding["severity"] == "high"
    assert finding["confidence"] == "high"
    assert finding["affected_object"]["table"] == "products"
    assert finding["affected_object"]["column"] == "description"


def test_demonstration_3_artifacts_exist_and_valid():
    demo_dir = Path(__file__).parent.parent / "docs" / "evidence" / "demo_3_detection_proof"

    json_path = demo_dir / "demo_3_output.json"
    sarif_path = demo_dir / "demo_3_output.sarif"
    log_path = demo_dir / "demo_3_console.log"
    summary_path = demo_dir / "DEMO_3_SUMMARY.md"

    assert json_path.exists(), "demo_3_output.json must exist"
    assert sarif_path.exists(), "demo_3_output.sarif must exist"
    assert log_path.exists(), "demo_3_console.log must exist"
    assert summary_path.exists(), "DEMO_3_SUMMARY.md must exist"

    # Verify JSON content
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["findings"][0]["rule_id"] == "SM002"
    assert data["policy"]["exit_code"] == 1

    # Verify SARIF content
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "SM002"

    # Verify log content
    log = log_path.read_text(encoding="utf-8")
    assert "SM002" in log
    assert "FAILED (POLICY)" in log or "exit_code 1" in log.lower() or "destructive column drop" in log.lower()
