"""Tests for CLI exit codes (0, 1, 2, 3), precedence, and commands."""

import shutil
from pathlib import Path
from typer.testing import CliRunner

from safemigrate.cli import app

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "safemigrate 0.1.0" in result.stdout


def test_cli_rules_list():
    result = runner.invoke(app, ["rules", "list"])
    assert result.exit_code == 0
    assert "SM001" in result.stdout
    assert "SM002" in result.stdout
    assert "SM010" in result.stdout


def test_cli_rules_show_valid():
    result = runner.invoke(app, ["rules", "show", "SM002"])
    assert result.exit_code == 0
    assert "Destructive Column Drop" in result.stdout
    assert "expand-contract" in result.stdout


def test_cli_rules_show_unknown_exit_code_2():
    result = runner.invoke(app, ["rules", "show", "SM999"])
    assert result.exit_code == 2


def test_exit_0_clean_migration(clean_fixtures_dir: Path):
    file_path = clean_fixtures_dir / "additive_vendor_note.sql"
    result = runner.invoke(app, ["scan", str(file_path), "--fail-on", "high"])
    assert result.exit_code == 0


def test_exit_0_advisory_below_threshold(risky_fixtures_dir: Path):
    # SM004 is Medium, so with --fail-on high it should pass with exit code 0
    file_path = risky_fixtures_dir / "sm004_unconcurrent_index.sql"
    result = runner.invoke(app, ["scan", str(file_path), "--fail-on", "high"])
    assert result.exit_code == 0


def test_exit_1_high_finding(risky_fixtures_dir: Path):
    file_path = risky_fixtures_dir / "drop_description.sql"
    result = runner.invoke(app, ["scan", str(file_path), "--fail-on", "high"])
    assert result.exit_code == 1


def test_exit_1_critical_finding(risky_fixtures_dir: Path):
    file_path = risky_fixtures_dir / "sm001_drop_table.sql"
    result = runner.invoke(app, ["scan", str(file_path), "--fail-on", "critical"])
    assert result.exit_code == 1


def test_exit_1_medium_fail_on_medium(risky_fixtures_dir: Path):
    file_path = risky_fixtures_dir / "sm004_unconcurrent_index.sql"
    result = runner.invoke(app, ["scan", str(file_path), "--fail-on", "medium"])
    assert result.exit_code == 1


def test_exit_2_missing_file():
    result = runner.invoke(app, ["scan", "nonexistent_migration.sql"])
    assert result.exit_code == 2


def test_exit_2_invalid_flag_option(clean_fixtures_dir: Path):
    file_path = clean_fixtures_dir / "additive_vendor_note.sql"
    result = runner.invoke(app, ["scan", str(file_path), "--fail-on", "invalid_severity"])
    assert result.exit_code == 2


def test_exit_2_unparseable_syntax(invalid_syntax_dir: Path):
    file_path = invalid_syntax_dir / "malformed_syntax.sql"
    result = runner.invoke(app, ["scan", str(file_path)])
    assert result.exit_code == 2


def test_exit_2_dynamic_sql(invalid_syntax_dir: Path):
    file_path = invalid_syntax_dir / "dynamic_sql_exec.sql"
    result = runner.invoke(app, ["scan", str(file_path)])
    assert result.exit_code == 2


def test_exit_2_precedence_over_code_1(tmp_path: Path, risky_fixtures_dir: Path, invalid_syntax_dir: Path):
    """
    CRITICAL INVARIANT TEST:
    When a scan encounters BOTH policy-breaching findings (which would trigger code 1)
    AND syntax/parse failures (which trigger code 2),
    Code 2 MUST take precedence over Code 1 (fail closed).
    """
    # Copy one risky file and one invalid file into a temp directory
    shutil.copy(risky_fixtures_dir / "drop_description.sql", tmp_path / "001_risky.sql")
    shutil.copy(invalid_syntax_dir / "malformed_syntax.sql", tmp_path / "002_broken.sql")

    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "high"])
    # Precedence requirement: MUST exit with 2, NOT 1
    assert result.exit_code == 2
