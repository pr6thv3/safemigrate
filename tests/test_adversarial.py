"""
Adversarial challenge test suite for SafeMigrate parser and rules.
Written by empirical challenger to stress-test AST parser, near-misses, and edge cases.
"""

from pathlib import Path
from typer.testing import CliRunner

from safemigrate.analyzer import MigrationAnalyzer
from safemigrate.cli import app
from safemigrate.models import Severity

runner = CliRunner()


def test_adv_quoted_staged_not_null_must_not_trigger_sm006():
    """
    CHALLENGE: Quoted identifiers in 3-step staged NOT NULL validation pattern.
    Should be recognized as safe near-miss (0 findings), NOT trigger SM006.
    """
    analyzer = MigrationAnalyzer()
    sql_path = Path(__file__).parent / "fixtures" / "adversarial" / "adv_sm006_quoted_staged.sql"
    report = analyzer.scan_path(sql_path)
    sm006_findings = [f for f in report.findings if f.rule_id == "SM006"]
    # Staged check validation pattern is used; MUST NOT trigger SM006!
    assert len(sm006_findings) == 0, f"False positive: SM006 triggered on safe staged pattern: {sm006_findings}"


def test_adv_unstaged_fk_with_comment_must_trigger_sm007():
    """
    CHALLENGE: Unstaged Foreign Key with comment containing 'NOT VALID'.
    Comment must NOT bypass rule SM007. MUST trigger SM007 finding!
    """
    analyzer = MigrationAnalyzer()
    sql_path = Path(__file__).parent / "fixtures" / "adversarial" / "adv_sm007_comment_bypass.sql"
    report = analyzer.scan_path(sql_path)
    sm007_findings = [f for f in report.findings if f.rule_id == "SM007"]
    # This is an unstaged foreign key; MUST trigger SM007!
    assert len(sm007_findings) >= 1, "False negative: SM007 bypassed by comment containing 'NOT VALID'!"


def test_adv_compound_alter_table_must_fail_closed_or_detect_sm003():
    """
    CHALLENGE: Multi-action ALTER TABLE changing column types.
    Must NOT pass silently with exit code 0!
    Must either detect SM003 or fail closed with exit code 2.
    """
    sql_path = Path(__file__).parent / "fixtures" / "adversarial" / "adv_sm003_multi_alter_type.sql"
    result = runner.invoke(app, ["scan", str(sql_path), "--fail-on", "high"])
    # Invariant: Unanalyzable or dangerous input MUST NOT pass policy with exit 0
    assert result.exit_code in (1, 2), f"Silent pass violation: expected exit code 1 or 2, got {result.exit_code}"


def test_adv_unnamed_check_must_fail_closed_or_detect_sm007():
    """
    CHALLENGE: Unnamed unstaged CHECK constraint.
    Must NOT pass silently with exit code 0 under --fail-on medium!
    """
    sql_path = Path(__file__).parent / "fixtures" / "adversarial" / "adv_sm007_unnamed_check.sql"
    result = runner.invoke(app, ["scan", str(sql_path), "--fail-on", "medium"])
    assert result.exit_code in (1, 2), f"Silent pass violation: expected exit code 1 or 2, got {result.exit_code}"


def test_adv_dynamic_sql_exec_fails_closed_exit_2():
    """
    CHALLENGE: Dynamic SQL execution with whitespace variation.
    Must fail closed with Exit Code 2.
    """
    sql_path = Path(__file__).parent / "fixtures" / "adversarial" / "adv_dynamic_sql_exec.sql"
    result = runner.invoke(app, ["scan", str(sql_path)])
    assert result.exit_code == 2


def test_adv_sm010_composite_indexes_leading_vs_inverted(tmp_path: Path):
    """
    CHALLENGE: SM010 composite indexes.
    Leading match passes; inverted match or partial match triggers SM010.
    """
    analyzer = MigrationAnalyzer()

    # Case A: Leading match (safe)
    case_a = tmp_path / "case_a.sql"
    case_a.write_text("""
    CREATE TABLE p ( id UUID PRIMARY KEY, t UUID, u UUID, UNIQUE(t, u) );
    CREATE TABLE c ( id UUID PRIMARY KEY, t UUID, u UUID, CONSTRAINT fk_c FOREIGN KEY (t, u) REFERENCES p(t, u) );
    CREATE INDEX idx_c ON c (t, u, id);
    """)
    rep_a = analyzer.scan_path(case_a)
    assert len([f for f in rep_a.findings if f.rule_id == "SM010"]) == 0

    # Case B: Inverted match (unsafe)
    case_b = tmp_path / "case_b.sql"
    case_b.write_text("""
    CREATE TABLE p ( id UUID PRIMARY KEY, t UUID, u UUID, UNIQUE(t, u) );
    CREATE TABLE c ( id UUID PRIMARY KEY, t UUID, u UUID, CONSTRAINT fk_c FOREIGN KEY (t, u) REFERENCES p(t, u) );
    CREATE INDEX idx_c ON c (u, t);
    """)
    rep_b = analyzer.scan_path(case_b)
    assert len([f for f in rep_b.findings if f.rule_id == "SM010"]) == 1
