"""Adversarial stress-test suite for SafeMigrate CLI exit codes and precedence.

Tests empirical boundaries of:
- Exit code 0: Clean migrations, staged near-misses, sub-threshold findings.
- Exit code 1: Policy threshold violations across all severity levels.
- Exit code 2: Syntax errors, dynamic SQL, missing files, corrupted binaries, bad flags.
- Exit code 3: Analyzer runtime exceptions.
- Fail-closed precedence: Code 2 strictly superseding Code 1 in mixed directories and files.
- Vulnerabilities / bugs identified during adversarial challenge.
"""

import json
from pathlib import Path
import shutil
import subprocess
from unittest.mock import patch
import pytest
from typer.testing import CliRunner

from safemigrate.cli import app
from safemigrate.models import Severity

runner = CliRunner()


# -----------------------------------------------------------------------------
# 1. Exit Code 0 Verification
# -----------------------------------------------------------------------------

def test_adversarial_exit_0_clean_and_staged_migrations(clean_fixtures_dir: Path):
    """Verifies that all valid clean fixtures and staged safe patterns return Exit Code 0."""
    for fixture in clean_fixtures_dir.glob("*.sql"):
        result = runner.invoke(app, ["scan", str(fixture), "--fail-on", "high", "--migration-transaction-mode", "not_wrapped"])
        assert result.exit_code == 0, f"Fixture {fixture.name} failed with exit code {result.exit_code}"


def test_adversarial_exit_0_below_threshold_matrix(risky_fixtures_dir: Path):
    """Verifies that findings below configured --fail-on threshold cleanly return Exit Code 0."""
    # SM004 (CREATE INDEX unconcurrent) is Medium severity
    sm004_path = risky_fixtures_dir / "sm004_unconcurrent_index.sql"
    result_high = runner.invoke(app, ["scan", str(sm004_path), "--fail-on", "high"])
    assert result_high.exit_code == 0
    result_crit = runner.invoke(app, ["scan", str(sm004_path), "--fail-on", "critical"])
    assert result_crit.exit_code == 0


def test_adversarial_exit_0_empty_directory(tmp_path: Path):
    """An empty directory containing no SQL migrations should return Exit Code 0."""
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0


# -----------------------------------------------------------------------------
# 2. Exit Code 1 Verification
# -----------------------------------------------------------------------------

def test_adversarial_exit_1_threshold_matrix(risky_fixtures_dir: Path):
    """Verifies exit code 1 across all severity thresholds and finding types."""
    # Medium finding vs medium threshold -> 1
    sm004_path = risky_fixtures_dir / "sm004_unconcurrent_index.sql"
    res_med = runner.invoke(app, ["scan", str(sm004_path), "--fail-on", "medium"])
    assert res_med.exit_code == 1

    # High finding vs high threshold -> 1
    drop_col_path = risky_fixtures_dir / "drop_description.sql"
    res_high = runner.invoke(app, ["scan", str(drop_col_path), "--fail-on", "high"])
    assert res_high.exit_code == 1

    # Critical finding vs critical threshold -> 1
    drop_tbl_path = risky_fixtures_dir / "sm001_drop_table.sql"
    res_crit = runner.invoke(app, ["scan", str(drop_tbl_path), "--fail-on", "critical"])
    assert res_crit.exit_code == 1


# -----------------------------------------------------------------------------
# 3. Exit Code 2 Verification
# -----------------------------------------------------------------------------

def test_adversarial_exit_2_syntax_error(invalid_syntax_dir: Path):
    """Unparseable syntax must fail with Exit Code 2."""
    res = runner.invoke(app, ["scan", str(invalid_syntax_dir / "malformed_syntax.sql")])
    assert res.exit_code == 2


def test_adversarial_exit_2_dynamic_sql(invalid_syntax_dir: Path):
    """Dynamic SQL constructs must fail with Exit Code 2."""
    res = runner.invoke(app, ["scan", str(invalid_syntax_dir / "dynamic_sql_exec.sql")])
    assert res.exit_code == 2


def test_adversarial_exit_2_missing_file_and_directory():
    """Non-existent file or directory paths must fail with Exit Code 2."""
    res_file = runner.invoke(app, ["scan", "/nonexistent/path/file.sql"])
    assert res_file.exit_code == 2
    res_dir = runner.invoke(app, ["scan", "/nonexistent/path/dir/"])
    assert res_dir.exit_code == 2


def test_adversarial_exit_2_invalid_cli_arguments(clean_fixtures_dir: Path):
    """Invalid CLI arguments and unrecognized enum options must fail with Exit Code 2."""
    valid_file = str(clean_fixtures_dir / "additive_vendor_note.sql")
    # Bad fail-on
    assert runner.invoke(app, ["scan", valid_file, "--fail-on", "invalid_level"]).exit_code == 2
    # Bad runner mode
    assert runner.invoke(app, ["scan", valid_file, "--migration-transaction-mode", "invalid_mode"]).exit_code == 2
    # Bad format
    assert runner.invoke(app, ["scan", valid_file, "--format", "invalid_format"]).exit_code == 2
    # Missing required argument
    assert runner.invoke(app, ["scan"]).exit_code == 2
    # Non-integer pg-version
    assert runner.invoke(app, ["scan", valid_file, "--pg-version", "eighteen"]).exit_code == 2
    # Unknown rule show
    assert runner.invoke(app, ["rules", "show", "SM_UNKNOWN"]).exit_code == 2


def test_adversarial_exit_2_corrupted_binary_sql(tmp_path: Path):
    """Binary/corrupted files with .sql suffix must fail closed with Exit Code 2."""
    corrupt_file = tmp_path / "corrupt.sql"
    corrupt_file.write_bytes(b"\x80\x81\xff\xfe\x00\x01\xfa\xce")
    result = runner.invoke(app, ["scan", str(corrupt_file), "--format", "json"])
    assert result.exit_code == 2
    data = json.loads(result.stdout)
    assert data["policy"]["exit_code"] == 2
    assert data["policy"]["passed"] is False
    assert len(data["diagnostics"]) >= 1


# -----------------------------------------------------------------------------
# 4. Exit Code 3 Verification (Runtime crash)
# -----------------------------------------------------------------------------

def test_adversarial_exit_3_runtime_crash_simulation():
    """Unhandled internal runtime exceptions must exit with code 3."""
    with patch("safemigrate.cli.MigrationAnalyzer.scan_path", side_effect=RuntimeError("Internal engine crash")):
        result = runner.invoke(app, ["scan", "dummy.sql"])
        assert result.exit_code == 3
        assert "SafeMigrate unexpected runtime error" in result.stderr


# -----------------------------------------------------------------------------
# 5. Fail-Closed Precedence (Code 2 strictly superseding Code 1)
# -----------------------------------------------------------------------------

def test_adversarial_fail_closed_precedence_dir_syntax_over_policy_1(tmp_path: Path, risky_fixtures_dir: Path, invalid_syntax_dir: Path):
    """
    CRITICAL: Directory contains both a policy violation (would be Code 1)
    and a syntax error (Code 2). Exit code MUST be 2.
    """
    shutil.copy(risky_fixtures_dir / "drop_description.sql", tmp_path / "001_policy_breach.sql")
    shutil.copy(invalid_syntax_dir / "malformed_syntax.sql", tmp_path / "002_syntax_error.sql")

    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "high"])
    assert result.exit_code == 2, f"Fail-closed precedence violated: got {result.exit_code}, expected 2"


def test_adversarial_fail_closed_precedence_dir_dynamic_sql_over_policy_1(tmp_path: Path, risky_fixtures_dir: Path, invalid_syntax_dir: Path):
    """Directory contains both policy violation and dynamic SQL -> Exit Code 2."""
    shutil.copy(risky_fixtures_dir / "drop_description.sql", tmp_path / "001_policy_breach.sql")
    shutil.copy(invalid_syntax_dir / "dynamic_sql_exec.sql", tmp_path / "002_dynamic_sql.sql")

    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "high"])
    assert result.exit_code == 2, f"Fail-closed precedence violated: got {result.exit_code}, expected 2"


def test_adversarial_fail_closed_precedence_single_file_syntax_over_policy_1(tmp_path: Path):
    """A single file containing both a policy violation and a syntax error -> Exit Code 2."""
    mixed_file = tmp_path / "mixed.sql"
    mixed_file.write_text(
        "ALTER TABLE products DROP COLUMN description;\n"
        "CREAT TABL broken ( id INT );\n",
        encoding="utf-8"
    )
    result = runner.invoke(app, ["scan", str(mixed_file), "--fail-on", "high"])
    assert result.exit_code == 2, f"Single-file fail-closed precedence violated: got {result.exit_code}, expected 2"


def test_adversarial_fail_closed_precedence_single_file_dynamic_sql_over_policy_1(tmp_path: Path):
    """A single file containing both a policy violation and dynamic SQL -> Exit Code 2."""
    mixed_file = tmp_path / "mixed.sql"
    mixed_file.write_text(
        "ALTER TABLE products DROP COLUMN description;\n"
        "EXECUTE 'DROP TABLE secret';\n",
        encoding="utf-8"
    )
    result = runner.invoke(app, ["scan", str(mixed_file), "--fail-on", "high"])
    assert result.exit_code == 2, f"Single-file dynamic SQL precedence violated: got {result.exit_code}, expected 2"


def test_adversarial_fail_closed_precedence_preserves_findings_in_json(tmp_path: Path, risky_fixtures_dir: Path, invalid_syntax_dir: Path):
    """When exit code 2 takes precedence, existing policy findings must still be preserved in the report."""
    shutil.copy(risky_fixtures_dir / "drop_description.sql", tmp_path / "001_policy_breach.sql")
    shutil.copy(invalid_syntax_dir / "malformed_syntax.sql", tmp_path / "002_syntax_error.sql")

    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "high", "--format", "json"])
    assert result.exit_code == 2
    data = json.loads(result.stdout)
    assert data["policy"]["exit_code"] == 2
    assert data["policy"]["passed"] is False
    assert len(data["findings"]) == 1, "Findings must be preserved even when failing closed with Exit Code 2"
    assert data["findings"][0]["rule_id"] == "SM002"
    assert len(data["diagnostics"]) >= 1
    assert data["summary"]["parse_errors"] >= 1


def test_adversarial_fail_closed_precedence_preserves_findings_in_sarif(tmp_path: Path, risky_fixtures_dir: Path, invalid_syntax_dir: Path):
    """SARIF output must reflect executionSuccessful=False and exitCode=2 while retaining results."""
    shutil.copy(risky_fixtures_dir / "drop_description.sql", tmp_path / "001_policy_breach.sql")
    shutil.copy(invalid_syntax_dir / "malformed_syntax.sql", tmp_path / "002_syntax_error.sql")

    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "high", "--format", "sarif"])
    assert result.exit_code == 2
    sarif = json.loads(result.stdout)
    run = sarif["runs"][0]
    inv = run["invocations"][0]
    assert inv["exitCode"] == 2
    assert inv["executionSuccessful"] is False
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "SM002"


# -----------------------------------------------------------------------------
# 6. Discovered Failure Modes & Bugs
# -----------------------------------------------------------------------------

def test_bug_unsupported_syntax_exp_command_fallback_bypasses_analysis(tmp_path: Path):
    """
    BUG DEMONSTRATION / VERIFICATION:
    When a statement contains unsupported syntax (e.g. 'ALTER TABLE users BROKEN_SYNTAX;'),
    SQLGlot falls back to AST node exp.Command.
    Now properly flagged as UNSUPPORTED_SYNTAX and fails closed with Exit Code 2.
    """
    sql_file = tmp_path / "unsupported_ddl.sql"
    sql_file.write_text("ALTER TABLE users BROKEN_SYNTAX;\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(sql_file)])
    assert result.exit_code == 2, f"Expected Exit Code 2 for unanalyzable SQL, got {result.exit_code}"


def test_bug_plpgsql_do_block_bypasses_analysis(tmp_path: Path):
    """
    BUG DEMONSTRATION / VERIFICATION:
    Procedural blocks like DO $$ BEGIN ... END $$ parse as exp.Command(this=DO).
    They are unanalyzable for AST rules and fail closed with Exit Code 2.
    """
    sql_file = tmp_path / "do_block.sql"
    sql_file.write_text("DO $$ BEGIN ALTER TABLE users DROP COLUMN email; END $$;\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(sql_file)])
    assert result.exit_code == 2, f"Expected Exit Code 2 for unsupported procedural command, got {result.exit_code}"


def test_bug_non_sql_file_scan_returns_exit_0(tmp_path: Path):
    """
    BUG DEMONSTRATION / VERIFICATION:
    When a user passes an explicit file path that does not end in .sql,
    analyzer.py rejects it with Exit Code 2.
    """
    non_sql_file = tmp_path / "migration.txt"
    non_sql_file.write_text("ALTER TABLE users DROP COLUMN email;\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(non_sql_file)])
    assert result.exit_code == 2, f"Expected Exit Code 2 for non-.sql file input, got {result.exit_code}"


def test_bug_duplicate_terminal_render_human_format(clean_fixtures_dir: Path):
    """
    Verifies that terminal human format renders cleanly without duplicate panels.
    """
    valid_file = clean_fixtures_dir / "additive_vendor_note.sql"
    proc = subprocess.run(
        [".venv/bin/safemigrate", "scan", str(valid_file), "--format", "human"],
        cwd=Path(__file__).parent.parent,
        capture_output=True,
        text=True
    )
    # Count occurrences of the scan header panel title
    header_count = proc.stdout.count("SafeMigrate Scan")
    assert header_count == 1, f"Expected exactly 1 header panel without duplicate rendering, found {header_count}"
