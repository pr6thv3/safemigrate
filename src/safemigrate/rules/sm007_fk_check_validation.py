"""Rule SM007: Foreign Key or CHECK Constraint Without Staged Validation."""

from typing import List
from sqlglot import exp

from safemigrate.models import AffectedObject, Confidence, Finding, Severity
from safemigrate.parser import ParsedStatement
from safemigrate.rules.base import AnalysisContext, Rule


class SM007FKCheckValidation(Rule):
    rule_id = "SM007"
    title = "Foreign Key or CHECK Constraint Addition Without Staged Validation"
    version = "1.0.0"
    default_severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    status = "First-Release (1.0)"
    description = "Detects adding foreign-key or CHECK constraints without staged validation (NOT VALID)."
    hazard_rationale = (
        "Adding an unstaged Foreign Key acquires SHARE ROW EXCLUSIVE lock on the child table and SHARE lock "
        "on the parent table while scanning the entire table. Adding an unstaged CHECK constraint acquires "
        "ACCESS EXCLUSIVE lock, blocking both concurrent reads and writes."
    )
    positive_example = "ALTER TABLE orders ADD CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users(id);"
    negative_example = (
        "ALTER TABLE orders ADD CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users(id) NOT VALID; "
        "ALTER TABLE orders VALIDATE CONSTRAINT fk_orders_user;"
    )
    remediation = (
        "Use 2-step staged constraint addition: (1) Add constraint with NOT VALID: "
        "'ALTER TABLE tbl ADD CONSTRAINT c_name ... NOT VALID;'; (2) Concurrently validate existing rows: "
        "'ALTER TABLE tbl VALIDATE CONSTRAINT c_name;'."
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
                is_constraint = isinstance(action, (exp.Constraint, exp.AddConstraint))
                if is_constraint:
                    fk = action.find(exp.ForeignKey)
                    check = action.find(exp.CheckColumnConstraint) or action.find(exp.Check)
                    if fk or check:
                        # Check if NOT VALID is present on parent Alter AST node or action args
                        is_not_valid = bool(node.args.get("not_valid")) or bool(getattr(action, "args", {}).get("not_valid"))

                        if not is_not_valid:
                            # Extract constraint name
                            constraint_obj = action.find(exp.Constraint)
                            c_name = "unnamed_constraint"
                            if constraint_obj and hasattr(constraint_obj, "this") and constraint_obj.this:
                                c_name = str(constraint_obj.this).strip('"')
                            elif hasattr(action, "this") and action.this:
                                c_name = str(action.this).strip('"')

                            c_kind = "FOREIGN KEY" if fk else "CHECK"
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
                                        constraint=c_name,
                                        operation="ADD_CONSTRAINT",
                                    ),
                                    evidence=f"ALTER TABLE {tbl_name} ADD CONSTRAINT {c_name} {c_kind} without NOT VALID",
                                    explanation=(
                                        f"Adding {c_kind} constraint '{c_name}' to '{tbl_name}' without NOT VALID "
                                        "performs an immediate full table validation scan while holding restrictive "
                                        "table locks, blocking concurrent writes."
                                    ),
                                    recommendation=self.remediation,
                                    context_used={
                                        "target_engine": "postgresql",
                                        "pg_version": context.pg_version,
                                        "not_valid": False,
                                    },
                                    context_not_known=[
                                        "table_row_count",
                                    ],
                                )
                            )

        return findings
