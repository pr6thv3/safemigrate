"""Tests for pure-static SQLGlot AST parser and syntax guardrails."""

from pathlib import Path
from safemigrate.models import DiagnosticType
from safemigrate.parser import parse_sql_content, parse_sql_file


def test_pure_static_parsing_valid_statements():
    sql = """
    -- Migration header
    DROP TABLE old_users CASCADE;
    ALTER TABLE orders ADD COLUMN tracking_code VARCHAR(100);
    """
    stmts, diags = parse_sql_content(sql, "test_valid.sql")
    assert len(diags) == 0
    assert len(stmts) == 2
    assert stmts[0].line == 3
    assert stmts[1].line == 4
    assert "DROP TABLE" in stmts[0].raw_statement
    assert "ALTER TABLE" in stmts[1].raw_statement


def test_parser_fails_closed_on_syntax_error(invalid_syntax_dir: Path):
    file_path = invalid_syntax_dir / "malformed_syntax.sql"
    stmts, diags = parse_sql_file(file_path)
    assert len(diags) > 0
    assert diags[0].type == DiagnosticType.PARSE_ERROR
    assert "SQLGlot failed to parse statement" in diags[0].message
    assert diags[0].line == 2


def test_parser_detects_dynamic_sql(invalid_syntax_dir: Path):
    file_path = invalid_syntax_dir / "dynamic_sql_exec.sql"
    stmts, diags = parse_sql_file(file_path)
    assert len(diags) > 0
    assert any(d.type == DiagnosticType.UNSUPPORTED_SYNTAX for d in diags)
    assert any("Dynamic SQL" in d.message for d in diags)


def test_parser_handles_empty_or_comment_only_content():
    sql = """
    -- Just comments
    /* Multi-line
       comment block */
    """
    stmts, diags = parse_sql_content(sql, "empty.sql")
    assert len(stmts) == 0
    assert len(diags) == 0


def test_parser_nonexistent_file():
    stmts, diags = parse_sql_file(Path("/nonexistent/path/file.sql"))
    assert len(stmts) == 0
    assert len(diags) == 1
    assert diags[0].type == DiagnosticType.PARSE_ERROR
    assert "Could not read SQL file" in diags[0].message
