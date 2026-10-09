"""Rule SM002: Destructive Column Drop."""

from typing import List
from sqlglot import exp

from safemigrate.models import AffectedObject, Confidence, Finding, Severity
from safemigrate.parser import ParsedStatement
from safemigrate.rules.base import AnalysisContext, Rule


class SM002DropColumn(Rule):
    rule_id = "SM002"
    title = "Destructive Column Drop"
    version = "1.0.0"
    default_severity = Severity.HIGH
    confidence = Confidence.HIGH
    status = "First-Release (1.0)"
    description = "Detects ALTER TABLE ... DROP COLUMN operations causing data loss and breaking rolling deployments."
    hazard_rationale = (
        "Dropping a column immediately breaks backward compatibility in rolling deployments where older "
        "application instances continue selecting or updating the column. Stored column data is permanently destroyed."
    )
    positive_example = "ALTER TABLE products DROP COLUMN description;"
    negative_example = "ALTER TABLE products ADD COLUMN description text;"
    remediation = (
        "Adopt expand-contract migration pattern: (1) Deprecate and remove column references from "
        "application code; (2) Deploy application release N; (3) Drop column in subsequent release N+1 "
        "after verifying no active queries access it."
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
                is_column_drop = False
                col_names: List[str] = []

                if isinstance(action, exp.Drop):
                    kind = str(action.args.get("kind") or "").upper()
                    if kind == "COLUMN":
                        is_column_drop = True
                        cols = action.args.get("tables") or []
                        if not cols and action.this:
                            cols = [action.this]
                        for c in cols:
                            col_name = c.name if hasattr(c, "name") else str(c).strip('"')
                            col_names.append(col_name)

                elif isinstance(action, exp.Command):
                    cmd_str = str(action.this).upper()
                    expr_str = str(action.args.get("expression") or "").strip()
                    if cmd_str == "DROP" and not expr_str.upper().startswith("CONSTRAINT"):
                        is_column_drop = True
                        # Clean column name from expression
                        cleaned = expr_str.replace("COLUMN", "").replace("column", "").strip()
                        cleaned = cleaned.split()[0].strip(';, "') if cleaned else "unknown"
                        col_names.append(cleaned)

                if is_column_drop:
                    for col_name in col_names:
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
                                    operation="DROP_COLUMN",
                                ),
                                evidence=f"ALTER TABLE {tbl_name} DROP COLUMN {col_name}",
                                explanation=(
                                    f"Dropping column '{col_name}' from table '{tbl_name}' immediately destroys "
                                    "column data and breaks backward compatibility for active application code "
                                    "in rolling deployments that continues to read or write this column."
                                ),
                                recommendation=self.remediation,
                                context_used={
                                    "target_engine": "postgresql",
                                    "pg_version": context.pg_version,
                                },
                                context_not_known=[
                                    "table_row_count",
                                    "live_query_dependencies",
                                ],
                            )
                        )

        return findings
