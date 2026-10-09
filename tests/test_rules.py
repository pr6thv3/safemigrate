"""Tests for all SafeMigrate release rules (SM001-SM007, SM010)."""

from pathlib import Path
from safemigrate.analyzer import MigrationAnalyzer
from safemigrate.models import DiagnosticType, Severity, TransactionMode


# --- SM001 ---
def test_sm001_positive(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(risky_fixtures_dir / "sm001_drop_table.sql")
    sm001_findings = [f for f in report.findings if f.rule_id == "SM001"]
    assert len(sm001_findings) == 2
    # First is DROP TABLE users (HIGH)
    assert sm001_findings[0].affected_object.table == "users"
    assert sm001_findings[0].severity == Severity.HIGH
    # Second is DROP TABLE IF EXISTS audit_logs CASCADE (CRITICAL)
    assert sm001_findings[1].affected_object.table == "audit_logs"
    assert sm001_findings[1].severity == Severity.CRITICAL


def test_sm001_near_miss(clean_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(clean_fixtures_dir / "sm001_near_miss.sql")
    sm001_findings = [f for f in report.findings if f.rule_id == "SM001"]
    assert len(sm001_findings) == 0


# --- SM002 ---
def test_sm002_positive(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(risky_fixtures_dir / "sm002_drop_column.sql")
    sm002_findings = [f for f in report.findings if f.rule_id == "SM002"]
    assert len(sm002_findings) >= 2
    assert sm002_findings[0].affected_object.table == "products"
    assert sm002_findings[0].affected_object.column == "description"
    assert sm002_findings[0].severity == Severity.HIGH


def test_sm002_near_miss(clean_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(clean_fixtures_dir / "sm002_near_miss.sql")
    sm002_findings = [f for f in report.findings if f.rule_id == "SM002"]
    assert len(sm002_findings) == 0


# --- SM003 ---
def test_sm003_positive(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(risky_fixtures_dir / "sm003_alter_type_rewrite.sql")
    sm003_findings = [f for f in report.findings if f.rule_id == "SM003"]
    assert len(sm003_findings) == 1
    assert sm003_findings[0].affected_object.table == "orders"
    assert sm003_findings[0].affected_object.column == "user_id"
    assert sm003_findings[0].severity == Severity.HIGH


def test_sm003_near_miss(clean_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(clean_fixtures_dir / "sm003_near_miss.sql")
    sm003_findings = [f for f in report.findings if f.rule_id == "SM003"]
    assert len(sm003_findings) == 0


# --- SM004 ---
def test_sm004_positive(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(risky_fixtures_dir / "sm004_unconcurrent_index.sql")
    sm004_findings = [f for f in report.findings if f.rule_id == "SM004"]
    assert len(sm004_findings) == 1
    assert sm004_findings[0].affected_object.table == "orders"
    assert sm004_findings[0].affected_object.index == "idx_orders_customer"
    assert sm004_findings[0].severity == Severity.MEDIUM


def test_sm004_near_miss(clean_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(clean_fixtures_dir / "sm004_near_miss.sql")
    sm004_findings = [f for f in report.findings if f.rule_id == "SM004"]
    assert len(sm004_findings) == 0


# --- SM005 ---
def test_sm005_in_file_tx(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(risky_fixtures_dir / "sm005_in_file_tx_concurrent.sql")
    sm005_findings = [f for f in report.findings if f.rule_id == "SM005"]
    assert len(sm005_findings) == 1
    assert sm005_findings[0].severity == Severity.HIGH
    assert sm005_findings[0].context_used.get("transaction_source") == "explicit_ast_block"


def test_sm005_runner_wrapped(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer(migration_transaction_mode=TransactionMode.WRAPPED)
    report = analyzer.scan_path(risky_fixtures_dir / "sm005_runner_wrapped_concurrent.sql")
    sm005_findings = [f for f in report.findings if f.rule_id == "SM005"]
    assert len(sm005_findings) == 1
    assert sm005_findings[0].severity == Severity.HIGH
    assert sm005_findings[0].context_used.get("migration_transaction_mode") == "wrapped"


def test_sm005_runner_not_wrapped_safe(clean_fixtures_dir: Path):
    analyzer = MigrationAnalyzer(migration_transaction_mode=TransactionMode.NOT_WRAPPED)
    report = analyzer.scan_path(clean_fixtures_dir / "sm005_near_miss_not_wrapped.sql")
    sm005_findings = [f for f in report.findings if f.rule_id == "SM005"]
    assert len(sm005_findings) == 0


def test_sm005_runner_unknown_advisory(context_fixtures_dir: Path):
    analyzer = MigrationAnalyzer(migration_transaction_mode=TransactionMode.UNKNOWN)
    report = analyzer.scan_path(context_fixtures_dir / "sm005_runner_unknown.sql")
    sm005_findings = [f for f in report.findings if f.rule_id == "SM005"]
    assert len(sm005_findings) == 1
    assert sm005_findings[0].severity == Severity.MEDIUM
    assert sm005_findings[0].context_used.get("migration_transaction_mode") == "unknown"


# --- SM006 ---
def test_sm006_positive(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(risky_fixtures_dir / "sm006_raw_set_not_null.sql")
    sm006_findings = [f for f in report.findings if f.rule_id == "SM006"]
    assert len(sm006_findings) == 2
    assert sm006_findings[0].affected_object.operation == "SET_NOT_NULL"
    assert sm006_findings[1].affected_object.operation == "ADD_COLUMN_NOT_NULL"


def test_sm006_staged_pattern_near_miss(clean_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(clean_fixtures_dir / "sm006_near_miss_staged_not_null.sql")
    sm006_findings = [f for f in report.findings if f.rule_id == "SM006"]
    assert len(sm006_findings) == 0


def test_sm006_default_column_near_miss(clean_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(clean_fixtures_dir / "sm006_near_miss_default_col.sql")
    sm006_findings = [f for f in report.findings if f.rule_id == "SM006"]
    assert len(sm006_findings) == 0


# --- SM007 ---
def test_sm007_positive(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(risky_fixtures_dir / "sm007_raw_fk_no_not_valid.sql")
    sm007_findings = [f for f in report.findings if f.rule_id == "SM007"]
    assert len(sm007_findings) == 2


def test_sm007_near_miss(clean_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(clean_fixtures_dir / "sm007_near_miss_not_valid.sql")
    sm007_findings = [f for f in report.findings if f.rule_id == "SM007"]
    assert len(sm007_findings) == 0


# --- SM010 ---
def test_sm010_positive_unindexed_fk(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(risky_fixtures_dir / "sm010_unindexed_fk.sql")
    sm010_findings = [f for f in report.findings if f.rule_id == "SM010"]
    assert len(sm010_findings) == 1
    assert sm010_findings[0].affected_object.table == "child_products"
    assert sm010_findings[0].affected_object.column == "vendor_id"
    assert sm010_findings[0].severity == Severity.MEDIUM


def test_sm010_exact_index_near_miss(clean_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(clean_fixtures_dir / "sm010_near_miss_exact_index.sql")
    sm010_findings = [f for f in report.findings if f.rule_id == "SM010"]
    assert len(sm010_findings) == 0


def test_sm010_composite_leading_index_near_miss(clean_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(clean_fixtures_dir / "sm010_near_miss_composite_leading.sql")
    sm010_findings = [f for f in report.findings if f.rule_id == "SM010"]
    assert len(sm010_findings) == 0


def test_sm010_composite_not_leading_triggers_finding(risky_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(risky_fixtures_dir / "sm010_composite_fk_not_leading.sql")
    sm010_findings = [f for f in report.findings if f.rule_id == "SM010"]
    assert len(sm010_findings) == 1
    assert sm010_findings[0].affected_object.table == "child_orders"
    assert sm010_findings[0].affected_object.column == "user_id"


def test_sm010_isolated_missing_context_diagnostic(context_fixtures_dir: Path):
    analyzer = MigrationAnalyzer()
    report = analyzer.scan_path(context_fixtures_dir / "sm010_isolated_fk_missing_context.sql")
    # Must NOT emit unverified finding
    sm010_findings = [f for f in report.findings if f.rule_id == "SM010"]
    assert len(sm010_findings) == 0
    # MUST emit insufficient_context diagnostic
    context_diags = [d for d in report.diagnostics if d.type == DiagnosticType.INSUFFICIENT_CONTEXT]
    assert len(context_diags) == 1
    assert "analyzed in isolation without preceding schema/index context" in context_diags[0].message
