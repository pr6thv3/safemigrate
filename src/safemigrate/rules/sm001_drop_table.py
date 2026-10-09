"""Rule SM001: Destructive Table Drop."""

from typing import List
from sqlglot import exp

from safemigrate.models import AffectedObject, Confidence, Finding, Severity
from safemigrate.parser import ParsedStatement
from safemigrate.rules.base import AnalysisContext, Rule


class SM001DropTable(Rule):
    rule_id = "SM001"
    title = "Destructive Table Drop"
    version = "1.0.0"
    default_severity = Severity.HIGH
    confidence = Confidence.HIGH
    status = "First-Release (1.0)"
    description = "Detects DROP TABLE operations causing permanent data loss and rolling deployment query failures."
    hazard_rationale = (
        "Dropping a table permanently deletes data and invalidates dependent views, foreign keys, "
        "and application queries. In rolling zero-downtime deployments, active application versions "
        "referencing the dropped table immediately crash with undefined table errors."
    )
    positive_example = "DROP TABLE users CASCADE;"
    negative_example = "DROP VIEW active_users_view;"
    remediation = (
        "Employ an expand-contract deprecation cycle: (1) Deprecate and remove table references from "
        "application code in release N; (2) Verify zero runtime queries access the table; (3) Archive "
        "data to cold storage and verify backups; (4) Drop the table in release N+1."
    )

    def evaluate(
        self,
        statement: ParsedStatement,
        context: AnalysisContext,
    ) -> List[Finding]:
        findings: List[Finding] = []
        node = statement.ast

        if isinstance(node, exp.Drop):
            kind = str(node.args.get("kind") or "").upper()
            if kind == "TABLE":
                is_cascade = bool(node.args.get("cascade"))
                severity = Severity.CRITICAL if is_cascade else Severity.HIGH

                # Extract target tables
                tables = node.args.get("tables") or []
                if not tables and node.this:
                    tables = [node.this]

                for tbl in tables:
                    tbl_name = tbl.name if hasattr(tbl, "name") else str(tbl).strip('"')
                    schema_name = tbl.db if hasattr(tbl, "db") and tbl.db else "public"

                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            rule_title=self.title,
                            rule_version=self.version,
                            severity=severity,
                            confidence=self.confidence,
                            file=statement.file,
                            line=statement.line,
                            column=statement.column,
                            statement=statement.raw_statement,
                            affected_object=AffectedObject(
                                schema_name=schema_name,
                                table=tbl_name,
                                operation="DROP_TABLE",
                            ),
                            evidence=f"DROP TABLE {'CASCADE' if is_cascade else ''} detected on '{tbl_name}'",
                            explanation=(
                                f"Dropping table '{tbl_name}' irrevocably deletes data and invalidates "
                                "dependent queries. In rolling deployments, running services referencing "
                                "this table will experience immediate query failures."
                            ),
                            recommendation=self.remediation,
                            context_used={
                                "target_engine": "postgresql",
                                "pg_version": context.pg_version,
                                "cascade": is_cascade,
                            },
                            context_not_known=[
                                "table_row_count",
                                "live_query_dependencies",
                                "cold_storage_backup_status",
                            ],
                        )
                    )

        return findings
