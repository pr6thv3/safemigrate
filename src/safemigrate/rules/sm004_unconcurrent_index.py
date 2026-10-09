"""Rule SM004: Non-Concurrent Index Creation Write Lockout."""

from typing import List
from sqlglot import exp

from safemigrate.models import AffectedObject, Confidence, Finding, Severity
from safemigrate.parser import ParsedStatement
from safemigrate.rules.base import AnalysisContext, Rule


class SM004UnconcurrentIndex(Rule):
    rule_id = "SM004"
    title = "Non-Concurrent Index Creation Write Lockout"
    version = "1.0.0"
    default_severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    status = "First-Release (1.0)"
    description = "Detects CREATE INDEX without CONCURRENTLY which takes a SHARE lock and blocks writes."
    hazard_rationale = (
        "Standard CREATE INDEX acquires a SHARE lock on the target table (or SHARE ROW EXCLUSIVE for UNIQUE indexes). "
        "While reads (SELECT) are permitted, all write operations (INSERT, UPDATE, DELETE) are blocked until index build finishes."
    )
    positive_example = "CREATE INDEX idx_orders_customer ON orders (customer_id);"
    negative_example = "CREATE INDEX CONCURRENTLY idx_orders_customer ON orders (customer_id);"
    remediation = (
        "Use CREATE INDEX CONCURRENTLY outside an explicit transaction block, or configure the migration "
        "runner to execute this statement non-transactionally."
    )

    def evaluate(
        self,
        statement: ParsedStatement,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []
        node = statement.ast

        if isinstance(node, exp.Create) and isinstance(node.this, exp.Index):
            is_concurrent = bool(node.args.get("concurrently"))
            if not is_concurrent:
                idx = node.this
                idx_name = idx.name if hasattr(idx, "name") else "unnamed_index"
                tbl = idx.args.get("table")
                tbl_name = tbl.name if hasattr(tbl, "name") and tbl else "unknown"
                schema_name = tbl.db if hasattr(tbl, "db") and tbl and tbl.db else "public"

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
                            index=idx_name,
                            operation="CREATE_INDEX",
                        ),
                        evidence=f"CREATE INDEX {idx_name} ON {tbl_name} without CONCURRENTLY",
                        explanation=(
                            f"Creating index '{idx_name}' on '{tbl_name}' without CONCURRENTLY acquires a SHARE lock, "
                            "blocking all concurrent write operations (INSERT, UPDATE, DELETE) until completed."
                        ),
                        recommendation=self.remediation,
                        context_used={
                            "target_engine": "postgresql",
                            "pg_version": context.pg_version,
                            "concurrently": False,
                        },
                        context_not_known=[
                            "table_row_count",
                            "write_traffic_frequency",
                        ],
                    )
                )

        return findings
