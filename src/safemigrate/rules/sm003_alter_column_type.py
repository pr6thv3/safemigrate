"""Rule SM003: Column Type Alteration Lock/Rewrite Hazard."""

from typing import List
from sqlglot import exp

from safemigrate.models import AffectedObject, Confidence, Finding, Severity
from safemigrate.parser import ParsedStatement
from safemigrate.rules.base import AnalysisContext, Rule


class SM003AlterColumnType(Rule):
    rule_id = "SM003"
    title = "Column Type Alteration Lock/Rewrite Hazard"
    version = "1.0.0"
    default_severity = Severity.HIGH
    confidence = Confidence.HIGH
    status = "First-Release (1.0)"
    description = "Detects ALTER COLUMN TYPE which acquires ACCESS EXCLUSIVE lock and may rewrite table rows."
    hazard_rationale = (
        "Altering a column type acquires an ACCESS EXCLUSIVE lock on the table, blocking all concurrent "
        "reads and writes. In PostgreSQL, most type changes force a full table rewrite and index rebuild."
    )
    positive_example = "ALTER TABLE orders ALTER COLUMN user_id TYPE BIGINT;"
    negative_example = "ALTER TABLE orders ALTER COLUMN status SET DEFAULT 'pending';"
    remediation = (
        "Employ staged column expansion: (1) Add a new column with the target type; (2) Dual-write "
        "in application code; (3) Backfill historical rows in bounded batches; (4) Switch application "
        "reads and writes to the new column; (5) Drop the old column in a later release."
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

            for action in node.args.get("actions", []):
                if isinstance(action, exp.AlterColumn) and action.args.get("dtype") is not None:
                    col_name = action.this.name if hasattr(action.this, "name") else str(action.this).strip('"')
                    target_type = action.args.get("dtype").sql("postgres")

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
                                operation="ALTER_COLUMN_TYPE",
                            ),
                            evidence=f"ALTER TABLE {tbl_name} ALTER COLUMN {col_name} TYPE {target_type}",
                            explanation=(
                                f"Altering column '{col_name}' on '{tbl_name}' to type '{target_type}' acquires an "
                                "ACCESS EXCLUSIVE lock and may trigger a full table rewrite and index rebuild, "
                                "blocking all concurrent reads and writes."
                            ),
                            recommendation=self.remediation,
                            context_used={
                                "target_engine": "postgresql",
                                "pg_version": context.pg_version,
                                "target_type": target_type,
                            },
                            context_not_known=[
                                "table_row_count",
                                "table_size_bytes",
                                "binary_compatibility_matrix",
                            ],
                        )
                    )

        return findings
