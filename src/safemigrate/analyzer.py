"""Analysis pipeline and chronological schema replay engine."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import re

from sqlglot import exp

from safemigrate.models import (
    Diagnostic,
    DiagnosticType,
    Finding,
    PolicyDecision,
    ScanReport,
    ScanSummary,
    Severity,
    TransactionMode,
)
from safemigrate.parser import ParsedStatement, parse_sql_file
from safemigrate.rules import ACTIVE_RULES
from safemigrate.rules.base import (
    AnalysisContext,
    ForeignKeyDefinition,
    SchemaState,
    TableState,
)
from safemigrate.rules.sm010_unindexed_foreign_key import SM010UnindexedForeignKey


def _extract_schema_elements_from_statement(
    stmt: ParsedStatement,
    schema_state: SchemaState,
    registered_fks: List[ForeignKeyDefinition],
) -> None:
    """Pass 1: Inspects statement to register tables, indexes, constraints into SchemaState."""
    node = stmt.ast

    # 1. CREATE TABLE
    if isinstance(node, exp.Create) and str(node.args.get("kind") or "").upper() == "TABLE":
        tbl = node.this.this if isinstance(node.this, exp.Schema) else node.this
        tbl_name = tbl.name if hasattr(tbl, "name") and tbl else str(tbl).strip('"')
        tbl_state = schema_state.get_or_create_table(tbl_name)
        tbl_state.created_in_history = True

        expressions = node.this.expressions if isinstance(node.this, exp.Schema) else []
        for expr in expressions:
            if isinstance(expr, exp.ColumnDef):
                col_name = expr.name.lower().strip('"')
                tbl_state.columns.add(col_name)

                # Check column-level constraints
                for c in expr.args.get("constraints", []):
                    # Primary key -> backing index
                    if isinstance(c.kind, exp.PrimaryKeyColumnConstraint):
                        tbl_state.indexes.append((col_name,))
                    # Unique -> backing index
                    elif isinstance(c.kind, exp.UniqueColumnConstraint):
                        tbl_state.indexes.append((col_name,))
                    # Foreign key
                    ref = c.find(exp.Reference)
                    if ref:
                        ref_tbl = ref.this.name if hasattr(ref.this, "name") else str(ref.this).strip('"')
                        ref_cols = tuple(
                            id_node.name.lower().strip('"') for id_node in ref.find_all(exp.Identifier)
                        )
                        registered_fks.append(
                            ForeignKeyDefinition(
                                constraint_name=f"fk_{tbl_name}_{col_name}",
                                child_table=tbl_name,
                                referencing_columns=(col_name,),
                                parent_table=ref_tbl,
                                referenced_columns=ref_cols or ("id",),
                                file=stmt.file,
                                line=stmt.line,
                                column=stmt.column,
                                statement=stmt.raw_statement,
                            )
                        )

            # Table-level constraints
            elif isinstance(expr, exp.Constraint):
                c_name = expr.name if hasattr(expr, "name") else "unnamed_constraint"
                # Table-level PRIMARY KEY or UNIQUE
                pk_or_uq = expr.find(exp.PrimaryKeyColumnConstraint) or expr.find(exp.UniqueColumnConstraint)
                if pk_or_uq:
                    cols = tuple(col.name.lower().strip('"') for col in expr.find_all(exp.Identifier) if col.name != c_name)
                    if cols:
                        tbl_state.indexes.append(cols)

                # Table-level FOREIGN KEY
                fk = expr.find(exp.ForeignKey)
                if fk:
                    fk_cols = tuple(col.name.lower().strip('"') for col in fk.expressions)
                    ref = expr.find(exp.Reference)
                    ref_tbl = "unknown"
                    ref_cols = ()
                    if ref:
                        ref_tbl = ref.this.name if hasattr(ref.this, "name") else str(ref.this).strip('"')
                        ref_cols = tuple(id_node.name.lower().strip('"') for id_node in ref.find_all(exp.Identifier))
                    registered_fks.append(
                        ForeignKeyDefinition(
                            constraint_name=c_name,
                            child_table=tbl_name,
                            referencing_columns=fk_cols,
                            parent_table=ref_tbl,
                            referenced_columns=ref_cols or ("id",),
                            file=stmt.file,
                            line=stmt.line,
                            column=stmt.column,
                            statement=stmt.raw_statement,
                        )
                    )

    # 2. CREATE INDEX
    elif isinstance(node, exp.Create) and isinstance(node.this, exp.Index):
        idx = node.this
        tbl = idx.args.get("table")
        tbl_name = tbl.name if hasattr(tbl, "name") and tbl else str(tbl).strip('"')
        tbl_state = schema_state.get_or_create_table(tbl_name)

        idx_cols: List[str] = []
        for ordered in idx.find_all(exp.Ordered):
            col_id = ordered.this.name if hasattr(ordered.this, "name") else str(ordered.this).strip('"')
            idx_cols.append(col_id.lower())
        if not idx_cols:
            for col in idx.find_all(exp.Column):
                idx_cols.append(col.name.lower().strip('"'))

        if idx_cols:
            tbl_state.indexes.append(tuple(idx_cols))

    # 3. ALTER TABLE
    elif isinstance(node, exp.Alter):
        tbl = node.this
        tbl_name = tbl.name if hasattr(tbl, "name") and tbl else str(tbl).strip('"')
        tbl_state = schema_state.get_or_create_table(tbl_name)

        for action in node.args.get("actions", []):
            if isinstance(action, (exp.Constraint, exp.AddConstraint)):
                c_name = "unnamed_constraint"
                constraint_obj = action.find(exp.Constraint)
                if constraint_obj and hasattr(constraint_obj, "this") and constraint_obj.this:
                    c_name = str(constraint_obj.this).strip('"')

                # Check if staged NOT NULL check constraint
                check = action.find(exp.CheckColumnConstraint) or action.find(exp.Check)
                if check:
                    # 1. AST extraction: inspect exp.Is nodes inside check constraint
                    for is_exp in check.find_all(exp.Is):
                        if isinstance(is_exp.expression, exp.Null) and is_exp.args.get("negate"):
                            col = is_exp.this
                            col_id = col.name if hasattr(col, "name") and col.name else str(col).strip('"')
                            if col_id:
                                tbl_state.staged_not_null_checks.add(col_id.lower().strip('"'))

                    # 2. Regex fallback supporting quoted, unquoted, and table-qualified column identifiers
                    sql_text = stmt.raw_statement.upper()
                    if "NOT NULL" in sql_text:
                        match = re.search(
                            r"\(\s*(?:[\"'\w]+\.)?[\"']?([a-zA-Z0-9_]+)[\"']?\s+IS\s+NOT\s+NULL\s*\)",
                            sql_text,
                        )
                        if match:
                            tbl_state.staged_not_null_checks.add(match.group(1).lower().strip('"'))

                # Foreign Key
                fk = action.find(exp.ForeignKey)
                if fk:
                    fk_cols = tuple(col.name.lower().strip('"') for col in fk.expressions)
                    ref = action.find(exp.Reference)
                    ref_tbl = "unknown"
                    ref_cols = ()
                    if ref:
                        ref_tbl = ref.this.name if hasattr(ref.this, "name") else str(ref.this).strip('"')
                        ref_cols = tuple(id_node.name.lower().strip('"') for id_node in ref.find_all(exp.Identifier))
                    registered_fks.append(
                        ForeignKeyDefinition(
                            constraint_name=c_name,
                            child_table=tbl_name,
                            referencing_columns=fk_cols,
                            parent_table=ref_tbl,
                            referenced_columns=ref_cols or ("id",),
                            file=stmt.file,
                            line=stmt.line,
                            column=stmt.column,
                            statement=stmt.raw_statement,
                        )
                    )

                # Primary Key / Unique
                pk_or_uq = action.find(exp.PrimaryKeyColumnConstraint) or action.find(exp.UniqueColumnConstraint)
                if pk_or_uq:
                    cols = tuple(
                        col.name.lower().strip('"')
                        for col in action.find_all(exp.Identifier)
                        if col.name != c_name
                    )
                    if cols:
                        tbl_state.indexes.append(cols)


class MigrationAnalyzer:
    """Coordinates parsing, schema replay, AST rule evaluation, and policy gating."""

    def __init__(
        self,
        pg_version: int = 18,
        migration_transaction_mode: TransactionMode = TransactionMode.UNKNOWN,
        fail_on: Severity = Severity.HIGH,
        deterministic: bool = False,
    ):
        self.pg_version = pg_version
        self.migration_transaction_mode = migration_transaction_mode
        self.fail_on = fail_on
        self.deterministic = deterministic

    def scan_path(self, target_path: Path) -> ScanReport:
        """Statically scans a single file or directory of migration SQL scripts."""
        if not target_path.exists():
            return ScanReport(
                scan_timestamp=None if self.deterministic else datetime.now(timezone.utc).isoformat(),
                target_engine="postgresql",
                pg_version=self.pg_version,
                migration_transaction_mode=self.migration_transaction_mode,
                scanned_files=[],
                diagnostics=[
                    Diagnostic(
                        type=DiagnosticType.PARSE_ERROR,
                        file=str(target_path),
                        line=1,
                        column=1,
                        message=f"Path does not exist: {target_path}",
                    )
                ],
                findings=[],
                summary=ScanSummary(
                    total_files=0,
                    total_statements=0,
                    total_findings=0,
                    severities={s.value: 0 for s in Severity},
                    parse_errors=1,
                ),
                policy=PolicyDecision(
                    fail_on=self.fail_on,
                    passed=False,
                    exit_code=2,
                ),
            )

        # Collect files
        sql_files: List[Path] = []
        is_directory_scan = target_path.is_dir()
        if target_path.is_file():
            if target_path.suffix.lower() != ".sql":
                return ScanReport(
                    scan_timestamp=None if self.deterministic else datetime.now(timezone.utc).isoformat(),
                    target_engine="postgresql",
                    pg_version=self.pg_version,
                    migration_transaction_mode=self.migration_transaction_mode,
                    scanned_files=[],
                    diagnostics=[
                        Diagnostic(
                            type=DiagnosticType.PARSE_ERROR,
                            file=str(target_path),
                            line=1,
                            column=1,
                            message=f"Target file is not a SQL file: {target_path}",
                        )
                    ],
                    findings=[],
                    summary=ScanSummary(
                        total_files=0,
                        total_statements=0,
                        total_findings=0,
                        severities={s.value: 0 for s in Severity},
                        parse_errors=1,
                    ),
                    policy=PolicyDecision(
                        fail_on=self.fail_on,
                        passed=False,
                        exit_code=2,
                    ),
                )
            sql_files = [target_path]
        elif target_path.is_dir():
            sql_files = sorted(list(target_path.rglob("*.sql")), key=lambda p: str(p))
        else:
            return ScanReport(
                scan_timestamp=None if self.deterministic else datetime.now(timezone.utc).isoformat(),
                target_engine="postgresql",
                pg_version=self.pg_version,
                migration_transaction_mode=self.migration_transaction_mode,
                scanned_files=[],
                diagnostics=[
                    Diagnostic(
                        type=DiagnosticType.PARSE_ERROR,
                        file=str(target_path),
                        line=1,
                        column=1,
                        message=f"Target path is neither a regular file nor a directory: {target_path}",
                    )
                ],
                findings=[],
                summary=ScanSummary(
                    total_files=0,
                    total_statements=0,
                    total_findings=0,
                    severities={s.value: 0 for s in Severity},
                    parse_errors=1,
                ),
                policy=PolicyDecision(
                    fail_on=self.fail_on,
                    passed=False,
                    exit_code=2,
                ),
            )

        # Handle empty directory cleanly (Exit 0)
        if not sql_files:
            return ScanReport(
                scan_timestamp=None if self.deterministic else datetime.now(timezone.utc).isoformat(),
                target_engine="postgresql",
                pg_version=self.pg_version,
                migration_transaction_mode=self.migration_transaction_mode,
                scanned_files=[],
                diagnostics=[],
                findings=[],
                summary=ScanSummary(
                    total_files=0,
                    total_statements=0,
                    total_findings=0,
                    severities={s.value: 0 for s in Severity},
                    parse_errors=0,
                ),
                policy=PolicyDecision(
                    fail_on=self.fail_on,
                    passed=True,
                    exit_code=0,
                ),
            )

        all_diagnostics: List[Diagnostic] = []
        all_findings: List[Finding] = []
        scanned_file_rel_paths: List[str] = []
        total_statement_count = 0

        schema_state = SchemaState()
        registered_fks: List[ForeignKeyDefinition] = []

        file_stmts_map: Dict[str, List[ParsedStatement]] = {}
        file_tx_map: Dict[str, bool] = {}

        # PASS 1: Parse all files and replay schema state
        for file_path in sql_files:
            # Normalize path representation
            try:
                rel_path = str(file_path.relative_to(Path.cwd()))
            except ValueError:
                rel_path = str(file_path)
            scanned_file_rel_paths.append(rel_path)

            stmts, diags = parse_sql_file(file_path)
            all_diagnostics.extend(diags)

            # Check if file has in-file transaction block
            has_tx = any(isinstance(s.ast, (exp.Transaction, exp.Commit)) for s in stmts)
            file_tx_map[rel_path] = has_tx
            file_stmts_map[rel_path] = stmts
            total_statement_count += len(stmts)

            # Replay schema elements
            for s in stmts:
                # Update file path to normalized relative path
                s.file = rel_path
                _extract_schema_elements_from_statement(s, schema_state, registered_fks)

        # PASS 2: Rule evaluation across statements
        for rel_path, stmts in file_stmts_map.items():
            context = AnalysisContext(
                pg_version=self.pg_version,
                migration_transaction_mode=self.migration_transaction_mode,
                file_has_explicit_transaction=file_tx_map[rel_path],
                schema_state=schema_state,
                current_file_statements=stmts,
            )

            for stmt in stmts:
                for rule in ACTIVE_RULES:
                    # Skip SM010 here; evaluated across schema state below
                    if rule.rule_id == "SM010":
                        continue
                    stmt_findings = rule.evaluate(stmt, context)
                    all_findings.extend(stmt_findings)

        # PASS 3: Context-aware SM010 Evaluation
        sm010_rule = SM010UnindexedForeignKey()
        context_sm010 = AnalysisContext(
            pg_version=self.pg_version,
            migration_transaction_mode=self.migration_transaction_mode,
            schema_state=schema_state,
        )

        for fk in registered_fks:
            tbl_normalized = fk.child_table.lower().strip('"')
            tbl_state = schema_state.tables.get(tbl_normalized)

            # Check if we have complete context for this table
            if tbl_state is None or not tbl_state.created_in_history:
                # Isolated foreign key without preceding table creation history
                all_diagnostics.append(
                    Diagnostic(
                        type=DiagnosticType.INSUFFICIENT_CONTEXT,
                        file=fk.file,
                        line=fk.line,
                        column=fk.column,
                        message=(
                            f"Foreign key '{fk.constraint_name}' on '{fk.child_table}"
                            f"({', '.join(fk.referencing_columns)})' analyzed in isolation without preceding schema/index context; "
                            "cannot verify whether an existing index covers referencing columns."
                        ),
                    )
                )
            else:
                # Full history available -> Evaluate index coverage
                fk_findings = sm010_rule.evaluate_foreign_key(fk, context_sm010)
                all_findings.extend(fk_findings)

        # Deterministic sorting of findings: (file, line, column, rule_id)
        all_findings.sort(key=lambda f: (f.file, f.line, f.column, f.rule_id))

        # Severity counts
        severity_counts = {s.value: 0 for s in Severity}
        for f in all_findings:
            severity_counts[f.severity.value] += 1

        # Parse errors count (blocking diagnostics)
        blocking_diags = [
            d for d in all_diagnostics if d.type in (DiagnosticType.PARSE_ERROR, DiagnosticType.UNSUPPORTED_SYNTAX)
        ]
        parse_errors_count = len(blocking_diags)

        # Policy decision
        policy_breached = any(f.severity.breaches(self.fail_on) for f in all_findings)

        # Exit code determination with fail-closed precedence (code 2 precedes code 1)
        if parse_errors_count > 0:
            exit_code = 2
            passed = False
        elif policy_breached:
            exit_code = 1
            passed = False
        else:
            exit_code = 0
            passed = True

        summary = ScanSummary(
            total_files=len(scanned_file_rel_paths),
            total_statements=total_statement_count,
            total_findings=len(all_findings),
            severities=severity_counts,
            parse_errors=parse_errors_count,
        )

        policy = PolicyDecision(
            fail_on=self.fail_on,
            passed=passed,
            exit_code=exit_code,
        )

        return ScanReport(
            schema_version="1.0",
            tool={"name": "safemigrate", "version": "0.1.0"},
            scan_timestamp=None if self.deterministic else datetime.now(timezone.utc).isoformat(),
            target_engine="postgresql",
            pg_version=self.pg_version,
            migration_transaction_mode=self.migration_transaction_mode,
            scanned_files=scanned_file_rel_paths,
            diagnostics=all_diagnostics,
            findings=all_findings,
            summary=summary,
            policy=policy,
        )
