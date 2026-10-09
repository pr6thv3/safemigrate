"""Rule SM010: Unindexed Foreign Key Referencing Columns."""

from typing import List, Tuple
from sqlglot import exp

from safemigrate.models import AffectedObject, Confidence, Finding, Severity
from safemigrate.parser import ParsedStatement
from safemigrate.rules.base import AnalysisContext, ForeignKeyDefinition, Rule


def is_foreign_key_covered(
    fk_cols: Tuple[str, ...],
    indexes: List[Tuple[str, ...]],
) -> bool:
    """
    Checks whether any index on the table has the FK referencing columns
    as its LEADING columns.
    Example:
      fk_cols = ('user_id',)
      idx = ('user_id', 'created_at') -> True (leading match)
      idx = ('created_at', 'user_id') -> False (not leading)
    """
    fk_lower = tuple(c.lower().strip('"') for c in fk_cols)
    for idx_cols in indexes:
        idx_lower = tuple(c.lower().strip('"') for c in idx_cols)
        if len(idx_lower) >= len(fk_lower) and idx_lower[: len(fk_lower)] == fk_lower:
            return True
    return False


class SM010UnindexedForeignKey(Rule):
    rule_id = "SM010"
    title = "Unindexed Foreign Key Referencing Columns"
    version = "1.0.0"
    default_severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    status = "First-Release (1.0)"
    description = "Detects foreign keys lacking supporting index on referencing columns (accounting for composite index leading column)."
    hazard_rationale = (
        "When rows in the parent table are updated or deleted, PostgreSQL must lock or sequentially scan "
        "the child table to enforce referential integrity. Without an index on the child referencing columns, "
        "parent updates/deletes cause full table scans and severe lock queueing on the child table."
    )
    positive_example = (
        "CREATE TABLE child_products ( id UUID PRIMARY KEY, vendor_id UUID REFERENCES parent_vendors(id) );"
    )
    negative_example = (
        "CREATE TABLE child_orders ( id UUID PRIMARY KEY, user_id UUID REFERENCES users(id), created_at TIMESTAMPTZ ); "
        "CREATE INDEX idx_child_orders_user_created ON child_orders (user_id, created_at);"
    )
    remediation = (
        "Create a supporting index on the foreign key referencing columns on the child table: "
        "'CREATE INDEX idx_{child_table}_{referencing_column} ON {child_table} ({referencing_column});'."
    )

    def evaluate(
        self,
        statement: ParsedStatement,
        context: AnalysisContext,
    ) -> List[Finding]:
        # Statement-level evaluation is handled as part of the schema replay pass in analyzer.py
        # Here we can also inspect statements that directly declare foreign keys if table state is known
        return []

    def evaluate_foreign_key(
        self,
        fk: ForeignKeyDefinition,
        context: AnalysisContext,
    ) -> List[Finding]:
        """Evaluates a registered foreign key against the replayed schema state."""
        tbl_state = context.schema_state.get_or_create_table(fk.child_table)

        # Check if index covers the foreign key
        if is_foreign_key_covered(fk.referencing_columns, tbl_state.indexes):
            return []

        col_str = ", ".join(fk.referencing_columns)
        first_col = fk.referencing_columns[0] if fk.referencing_columns else "unknown"

        return [
            Finding(
                rule_id=self.rule_id,
                rule_title=self.title,
                rule_version=self.version,
                severity=self.default_severity,
                confidence=self.confidence,
                file=fk.file,
                line=fk.line,
                column=fk.column,
                statement=fk.statement,
                affected_object=AffectedObject(
                    schema_name="public",
                    table=fk.child_table,
                    column=first_col,
                    constraint=fk.constraint_name,
                    operation="FOREIGN_KEY",
                ),
                evidence=f"Foreign key '{fk.constraint_name}' on {fk.child_table}({col_str}) has no supporting index",
                explanation=(
                    f"Child table '{fk.child_table}' foreign key referencing columns ({col_str}) referencing "
                    f"'{fk.parent_table}' are not covered by any index with leading column match. "
                    f"Deletes or primary key updates on '{fk.parent_table}' will force sequential scans on '{fk.child_table}'."
                ),
                recommendation=f"CREATE INDEX idx_{fk.child_table}_{first_col} ON {fk.child_table} ({col_str});",
                context_used={
                    "target_engine": "postgresql",
                    "pg_version": context.pg_version,
                    "existing_indexes": [list(idx) for idx in tbl_state.indexes],
                },
                context_not_known=[
                    "table_row_count",
                    "parent_table_delete_frequency",
                ],
            )
        ]
