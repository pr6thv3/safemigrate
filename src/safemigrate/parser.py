"""Pure-static PostgreSQL DDL parser using SQLGlot."""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple
import re

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError
from sqlglot.tokens import Token, TokenType

from safemigrate.models import Diagnostic, DiagnosticType


@dataclass
class ParsedStatement:
    """Represents a statically parsed SQL statement with location and raw source."""
    ast: exp.Expression
    file: str
    line: int
    column: int
    raw_statement: str


def _detect_dynamic_sql(raw_sql: str) -> Optional[str]:
    """Check if raw SQL contains unanalyzable dynamic SQL constructs."""
    upper = raw_sql.upper()
    if "EXECUTE FORMAT(" in upper:
        return "Dynamic SQL statement 'EXECUTE format(...)' cannot be statically analyzed"
    if re.search(r"\bEXECUTE\s+['\"]", upper):
        return "Dynamic string execution 'EXECUTE ...' cannot be statically analyzed"
    return None


def parse_sql_content(
    sql_content: str, file_path: str = "<stdin>"
) -> Tuple[List[ParsedStatement], List[Diagnostic]]:
    """
    Statically parses PostgreSQL SQL content into AST statements and diagnostics.
    Guarantees pure static analysis with zero database interaction.
    Fails closed on parse errors or unsupported dynamic SQL.
    """
    diagnostics: List[Diagnostic] = []
    statements: List[ParsedStatement] = []

    # Check for empty content
    stripped = sql_content.strip()
    if not stripped:
        return statements, diagnostics

    # Attempt tokenization
    try:
        tokens = sqlglot.tokenize(sql_content, read="postgres")
    except Exception as exc:
        diagnostics.append(
            Diagnostic(
                type=DiagnosticType.PARSE_ERROR,
                file=file_path,
                line=1,
                column=1,
                message=f"Failed to tokenize PostgreSQL SQL: {exc}",
            )
        )
        return statements, diagnostics

    if not tokens:
        return statements, diagnostics

    # Split tokens by statement boundaries (semicolons)
    stmt_tokens_list: List[List[Token]] = []
    current_tokens: List[Token] = []
    for t in tokens:
        current_tokens.append(t)
        if t.token_type == TokenType.SEMICOLON:
            stmt_tokens_list.append(current_tokens)
            current_tokens = []
    if current_tokens:
        stmt_tokens_list.append(current_tokens)

    # Parse each statement
    for stmt_tokens in stmt_tokens_list:
        # Filter out trailing whitespace/semicolons
        non_comment_tokens = [t for t in stmt_tokens if t.token_type != TokenType.SEMICOLON]
        if not non_comment_tokens:
            continue

        first_tok = non_comment_tokens[0]
        last_tok = stmt_tokens[-1]
        stmt_start_line = first_tok.line
        stmt_start_col = first_tok.col
        raw_stmt = sql_content[first_tok.start : last_tok.end + 1].strip()

        # Check for dynamic SQL in raw statement
        dyn_error = _detect_dynamic_sql(raw_stmt)
        if dyn_error:
            diagnostics.append(
                Diagnostic(
                    type=DiagnosticType.UNSUPPORTED_SYNTAX,
                    file=file_path,
                    line=stmt_start_line,
                    column=stmt_start_col,
                    message=dyn_error,
                )
            )
            continue

        # Parse with SQLGlot
        try:
            parsed = sqlglot.parse(raw_stmt, read="postgres")
            valid_stmts = [s for s in parsed if s is not None]
            if not valid_stmts:
                continue

            for ast_node in valid_stmts:
                # Check if AST represents an unsupported command that fell back
                if isinstance(ast_node, exp.Command):
                    cmd_name = str(ast_node.this).upper()
                    if cmd_name == "EXECUTE" or "EXECUTE" in ast_node.sql("postgres").upper():
                        diagnostics.append(
                            Diagnostic(
                                type=DiagnosticType.UNSUPPORTED_SYNTAX,
                                file=file_path,
                                line=stmt_start_line,
                                column=stmt_start_col,
                                message=f"Dynamic SQL or unsupported procedural command: {raw_stmt}",
                            )
                        )
                        continue

                statements.append(
                    ParsedStatement(
                        ast=ast_node,
                        file=file_path,
                        line=stmt_start_line,
                        column=stmt_start_col,
                        raw_statement=raw_stmt,
                    )
                )
        except ParseError as exc:
            err_line = stmt_start_line
            err_col = stmt_start_col
            err_msg = str(exc)
            if hasattr(exc, "errors") and exc.errors:
                first_err = exc.errors[0]
                rel_line = first_err.get("line") or 1
                err_line = (stmt_start_line - 1) + rel_line
                err_col = first_err.get("col") or stmt_start_col
                err_msg = first_err.get("description") or str(exc)

            diagnostics.append(
                Diagnostic(
                    type=DiagnosticType.PARSE_ERROR,
                    file=file_path,
                    line=err_line,
                    column=err_col,
                    message=f"SQLGlot failed to parse statement: {err_msg}",
                )
            )
        except Exception as exc:
            diagnostics.append(
                Diagnostic(
                    type=DiagnosticType.PARSE_ERROR,
                    file=file_path,
                    line=stmt_start_line,
                    column=stmt_start_col,
                    message=f"Syntax parsing exception: {exc}",
                )
            )

    return statements, diagnostics


def parse_sql_file(file_path: Path) -> Tuple[List[ParsedStatement], List[Diagnostic]]:
    """Reads and statically parses a single SQL migration file."""
    try:
        content = file_path.read_text(encoding="utf-8")
        return parse_sql_content(content, file_path=str(file_path))
    except Exception as exc:
        return [], [
            Diagnostic(
                type=DiagnosticType.PARSE_ERROR,
                file=str(file_path),
                line=1,
                column=1,
                message=f"Could not read SQL file: {exc}",
            )
        ]
