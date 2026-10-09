"""Rule SM006: Add NOT NULL or Constraint Without Staged Validation."""

from typing import List
from sqlglot import exp

from safemigrate.models import AffectedObject, Confidence, Finding, Severity
from safemigrate.parser import ParsedStatement
from safemigrate.rules.base import AnalysisContext, Rule


class SM006ConstraintLock(Rule):
    rule_id = "SM006"
    title = "Add NOT NULL or Constraint Without Staged Validation"
    version = "1.0.0"
    default_severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    status = "First-Release (1.0)"
    description = "Detects adding NOT NULL or constraint directly without staged validation causing table scan lockups."
    hazard_rationale = (
        "Applying SET NOT NULL directly to an existing column requires a full table scan while holding an "
        "ACCESS EXCLUSIVE lock to verify no NULL values exist. Adding a NOT NULL column without a default value "
        "fails immediately if rows already exist."
    )
    positive_example = "ALTER TABLE users ALTER COLUMN phone_number SET NOT NULL;"
    negative_example = (
        "ALTER TABLE users ADD CONSTRAINT chk_not_null CHECK (phone_number IS NOT NULL) NOT VALID; "
        "ALTER TABLE users VALIDATE CONSTRAINT chk_not_null; "
        "ALTER TABLE users ALTER COLUMN phone_number SET NOT NULL;"
    )
    remediation = (
        "Use 3-step staged NOT NULL validation pattern (PostgreSQL 12+): "
        "(1) ALTER TABLE tbl ADD CONSTRAINT chk_col_not_null CHECK (col IS NOT NULL) NOT VALID; "
        "(2) ALTER TABLE tbl VALIDATE CONSTRAINT chk_col_not_null; "
        "(3) ALTER TABLE tbl ALTER COLUMN col SET NOT NULL;"
    )

    def evaluate(
        self,
        statement: ParsedStatement,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []
        node = statement.ast

        if isinstance(node, exp.Alter):
            tbl = node.this
            tbl_name = tbl.name if hasattr(tbl, "name") else str(tbl).strip('"')
            schema_name = tbl.db if hasattr(tbl, "db") and tbl.db else "public"
            table_state = context.schema_state.get_or_create_table(tbl_name)

            for action in node.args.get("actions", []):
                # Variant 1: SET NOT NULL on existing column
                if isinstance(action, exp.AlterColumn) and action.args.get("dtype") is None:
                    is_set_not_null = (
                        action.args.get("allow_null") is False
                        or "SET NOT NULL" in action.sql("postgres").upper()
                    )
                    if is_set_not_null:
                        col_name = action.this.name if hasattr(action.this, "name") else str(action.this).strip('"')
                        # Check if staged validation check exists for this column
                        col_normalized = col_name.lower().strip('"')
                        if col_normalized not in table_state.staged_not_null_checks:
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    rule_title=self.title,
                                    rule_version=self.version,
                                    severity=self.default_severity,
                                    confidence=self.confidence,
                                    file=statement.file,
                                    line=statement.line,
                                    column=statement.column,
                                    statement=statement.raw_statement,
                                    affected_object=AffectedObject(
                                        schema_name=schema_name,
                                        table=tbl_name,
                                        column=col_name,
                                        operation="SET_NOT_NULL",
                                    ),
                                    evidence=f"ALTER TABLE {tbl_name} ALTER COLUMN {col_name} SET NOT NULL",
                                    explanation=(
                                        f"Applying 'SET NOT NULL' directly to column '{col_name}' on '{tbl_name}' performs "
                                        "a full table scan under ACCESS EXCLUSIVE lock, blocking all reads and writes."
                                    ),
                                    recommendation=self.remediation,
                                    context_used={
                                        "target_engine": "postgresql",
                                        "pg_version": context.pg_version,
                                        "staged_pattern_detected": False,
                                    },
                                    context_not_known=[
                                        "table_row_count",
                                    ],
                                )
                            )

                # Variant 2: ADD COLUMN NOT NULL without default value
                elif isinstance(action, exp.ColumnDef):
                    col_name = action.this.name if hasattr(action.this, "name") else str(action.this).strip('"')
                    constraints = action.args.get("constraints", [])
                    has_not_null = any(
                        isinstance(c.kind, exp.NotNullColumnConstraint) for c in constraints
                    ) or "NOT NULL" in action.sql("postgres").upper()

                    has_default = any(
                        isinstance(c.kind, exp.DefaultColumnConstraint) for c in constraints
                    ) or action.args.get("default") is not None

                    if has_not_null and not has_default:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                rule_title=self.title,
                                rule_version=self.version,
                                severity=self.default_severity,
                                confidence=self.confidence,
                                file=statement.file,
                                line=statement.line,
                                column=statement.column,
                                statement=statement.raw_statement,
                                affected_object=AffectedObject(
                                    schema_name=schema_name,
                                    table=tbl_name,
                                    column=col_name,
                                    operation="ADD_COLUMN_NOT_NULL",
                                ),
                                evidence=f"ALTER TABLE {tbl_name} ADD COLUMN {col_name} NOT NULL without DEFAULT",
                                explanation=(
                                    f"Adding column '{col_name}' with NOT NULL constraint and no DEFAULT value requires "
                                    "the table to be empty or will fail immediately upon execution."
                                ),
                                recommendation="Add the column as NULLable first, backfill rows, and transition via staged validation.",
                                context_used={
                                    "target_engine": "postgresql",
                                    "pg_version": context.pg_version,
                                },
                                context_not_known=[
                                    "table_row_count",
                                ],
                            )
                        )

        return findings
