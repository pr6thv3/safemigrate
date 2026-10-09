"""Rule SM005: Transaction-Wrapped Concurrent Index Creation."""

from typing import List
from sqlglot import exp

from safemigrate.models import AffectedObject, Confidence, Finding, Severity, TransactionMode
from safemigrate.parser import ParsedStatement
from safemigrate.rules.base import AnalysisContext, Rule


class SM005TransactionConcurrent(Rule):
    rule_id = "SM005"
    title = "Transaction-Wrapped Concurrent Index Creation"
    version = "1.0.0"
    default_severity = Severity.HIGH
    confidence = Confidence.HIGH
    status = "First-Release (1.0)"
    description = "Detects CREATE INDEX CONCURRENTLY executed inside explicit or runner-wrapped transaction blocks."
    hazard_rationale = (
        "PostgreSQL strictly prohibits running CREATE INDEX CONCURRENTLY within a transaction block, raising: "
        "'ERROR: CREATE INDEX CONCURRENTLY cannot run inside a transaction block'. This causes immediate migration failure."
    )
    positive_example = "BEGIN; CREATE INDEX CONCURRENTLY idx_orders_created ON orders (created_at); COMMIT;"
    negative_example = "CREATE INDEX CONCURRENTLY idx_orders_created ON orders (created_at); -- with mode not_wrapped"
    remediation = (
        "Execute CREATE INDEX CONCURRENTLY non-transactionally: remove in-file BEGIN/COMMIT blocks, or configure "
        "your migration runner (e.g. node-pg-migrate transaction: false, Flyway, Prisma) to disable transaction wrapping."
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
            if is_concurrent:
                idx = node.this
                idx_name = idx.name if hasattr(idx, "name") else "unnamed_index"
                tbl = idx.args.get("table")
                tbl_name = tbl.name if hasattr(tbl, "name") and tbl else "unknown"
                schema_name = tbl.db if hasattr(tbl, "db") and tbl and tbl.db else "public"

                # Case 1: In-file explicit transaction
                if context.file_has_explicit_transaction:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            rule_title=self.title,
                            rule_version=self.version,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            file=statement.file,
                            line=statement.line,
                            column=statement.column,
                            statement=statement.raw_statement,
                            affected_object=AffectedObject(
                                schema_name=schema_name,
                                table=tbl_name,
                                index=idx_name,
                                operation="CREATE_INDEX_CONCURRENTLY",
                            ),
                            evidence=f"CREATE INDEX CONCURRENTLY {idx_name} within explicit transaction block",
                            explanation=(
                                f"Index '{idx_name}' is created with CONCURRENTLY inside an explicit transaction block. "
                                "PostgreSQL aborts immediately with 'ERROR: CREATE INDEX CONCURRENTLY cannot run inside a transaction block'."
                            ),
                            recommendation=self.remediation,
                            context_used={
                                "target_engine": "postgresql",
                                "pg_version": context.pg_version,
                                "transaction_source": "explicit_ast_block",
                                "migration_transaction_mode": context.migration_transaction_mode.value,
                            },
                            context_not_known=[],
                        )
                    )

                # Case 2: Configured runner mode is wrapped
                elif context.migration_transaction_mode == TransactionMode.WRAPPED:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            rule_title=self.title,
                            rule_version=self.version,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            file=statement.file,
                            line=statement.line,
                            column=statement.column,
                            statement=statement.raw_statement,
                            affected_object=AffectedObject(
                                schema_name=schema_name,
                                table=tbl_name,
                                index=idx_name,
                                operation="CREATE_INDEX_CONCURRENTLY",
                            ),
                            evidence=f"CREATE INDEX CONCURRENTLY {idx_name} with runner mode 'wrapped'",
                            explanation=(
                                f"CREATE INDEX CONCURRENTLY for '{idx_name}' is executed in a runner with "
                                "--migration-transaction-mode wrapped. PostgreSQL rejects CONCURRENTLY within transaction blocks."
                            ),
                            recommendation=self.remediation,
                            context_used={
                                "target_engine": "postgresql",
                                "pg_version": context.pg_version,
                                "migration_transaction_mode": "wrapped",
                            },
                            context_not_known=[],
                        )
                    )

                # Case 3: Mode is unknown -> emit advisory warning
                elif context.migration_transaction_mode == TransactionMode.UNKNOWN:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            rule_title=self.title,
                            rule_version=self.version,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            file=statement.file,
                            line=statement.line,
                            column=statement.column,
                            statement=statement.raw_statement,
                            affected_object=AffectedObject(
                                schema_name=schema_name,
                                table=tbl_name,
                                index=idx_name,
                                operation="CREATE_INDEX_CONCURRENTLY",
                            ),
                            evidence=f"CREATE INDEX CONCURRENTLY {idx_name} with unknown transaction mode",
                            explanation=(
                                f"CREATE INDEX CONCURRENTLY for '{idx_name}' requires non-transactional execution. "
                                "The migration runner transaction mode is currently 'unknown'. If your runner wraps "
                                "migrations by default (e.g. node-pg-migrate, Flyway, Prisma), this will fail at runtime."
                            ),
                            recommendation="Disambiguate runner behavior by passing --migration-transaction-mode [wrapped|not_wrapped].",
                            context_used={
                                "target_engine": "postgresql",
                                "pg_version": context.pg_version,
                                "migration_transaction_mode": "unknown",
                            },
                            context_not_known=[
                                "runner_transaction_wrapper_configured",
                            ],
                        )
                    )

                # Case 4: not_wrapped -> Safe! Return nothing.

        return findings
