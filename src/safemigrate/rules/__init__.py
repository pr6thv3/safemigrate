"""SafeMigrate rule registry and catalogue."""

from typing import Dict, List, Optional

from safemigrate.models import Confidence, RuleInfo, Severity
from safemigrate.rules.base import Rule
from safemigrate.rules.sm001_drop_table import SM001DropTable
from safemigrate.rules.sm002_drop_column import SM002DropColumn
from safemigrate.rules.sm003_alter_column_type import SM003AlterColumnType
from safemigrate.rules.sm004_unconcurrent_index import SM004UnconcurrentIndex
from safemigrate.rules.sm005_transaction_concurrent import SM005TransactionConcurrent
from safemigrate.rules.sm006_constraint_lock import SM006ConstraintLock
from safemigrate.rules.sm007_fk_check_validation import SM007FKCheckValidation
from safemigrate.rules.sm010_unindexed_foreign_key import SM010UnindexedForeignKey


# Active First-Release (1.0) Rules
ACTIVE_RULES: List[Rule] = [
    SM001DropTable(),
    SM002DropColumn(),
    SM003AlterColumnType(),
    SM004UnconcurrentIndex(),
    SM005TransactionConcurrent(),
    SM006ConstraintLock(),
    SM007FKCheckValidation(),
    SM010UnindexedForeignKey(),
]

ACTIVE_RULE_MAP: Dict[str, Rule] = {rule.rule_id.upper(): rule for rule in ACTIVE_RULES}

# Formally Documented Post-1.0 Roadmap Rules
ROADMAP_RULES: List[RuleInfo] = [
    RuleInfo(
        rule_id="SM008",
        title="Broad UPDATE/DELETE Without Bounded Predicate",
        version="0.1.0-draft",
        default_severity=Severity.HIGH,
        confidence=Confidence.LOW,
        status="Roadmap (Post-1.0)",
        description="Heuristic detecting unbounded UPDATE or DELETE statements locking large numbers of rows.",
        hazard_rationale="Unbounded DML holds row locks and generates massive WAL volume, triggering replication lag and table bloat.",
        positive_example="UPDATE orders SET status = 'archived';",
        negative_example="UPDATE orders SET status = 'archived' WHERE id IN (SELECT id FROM orders LIMIT 1000);",
        remediation="Execute batch updates in bounded loops with sleep intervals.",
    ),
    RuleInfo(
        rule_id="SM009",
        title="Immediate Table or Column Rename Compatibility Hazard",
        version="0.1.0-draft",
        default_severity=Severity.HIGH,
        confidence=Confidence.LOW,
        status="Roadmap (Post-1.0)",
        description="Heuristic detecting immediate renames of tables or columns that break rolling application deployments.",
        hazard_rationale="In rolling deployments, active application instances querying the old name fail immediately upon execution.",
        positive_example="ALTER TABLE products RENAME COLUMN title TO product_name;",
        negative_example="-- Expand-contract: add new column, sync data, deprecate old column",
        remediation="Use expand-contract pattern: add new column/view, dual-write, then drop old column after migration.",
    ),
    RuleInfo(
        rule_id="SM011",
        title="Risky Enum/Type Alteration Pattern",
        version="0.1.0-draft",
        default_severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        status="Roadmap (Post-1.0)",
        description="Detects enum type alterations that cannot be rolled back or require exclusive catalog locks.",
        hazard_rationale="Altering enum values in older PostgreSQL versions requires catalog locks or cannot be executed in transactions.",
        positive_example="ALTER TYPE order_status ADD VALUE 'disputed';",
        negative_example="-- Migrating enum to reference lookup table",
        remediation="Create a lookup table or review PostgreSQL version compatibility.",
    ),
    RuleInfo(
        rule_id="SM012",
        title="Potentially Unsafe Migration Transaction Ordering Pattern",
        version="0.1.0-draft",
        default_severity=Severity.LOW,
        confidence=Confidence.LOW,
        status="Roadmap (Post-1.0)",
        description="Heuristic detecting interleaving of DDL and DML operations within a single migration.",
        hazard_rationale="Mixing DDL and DML in long-running transactions prolongs lock acquisition windows.",
        positive_example="BEGIN; ALTER TABLE orders ADD COLUMN note text; UPDATE orders SET note = 'none'; COMMIT;",
        negative_example="-- Separate DDL migration from backfill data migration script",
        remediation="Separate structural DDL migrations from operational DML data backfills.",
    ),
]


def get_all_rules_info() -> List[RuleInfo]:
    """Returns combined catalog of all active and roadmap rules."""
    all_rules = [r.get_info() for r in ACTIVE_RULES]
    all_rules.extend(ROADMAP_RULES)
    all_rules.sort(key=lambda r: r.rule_id)
    return all_rules


def get_rule_info(rule_id: str) -> Optional[RuleInfo]:
    """Looks up rule by ID (case-insensitive) across active and roadmap rules."""
    normalized = rule_id.upper().strip()
    if normalized in ACTIVE_RULE_MAP:
        return ACTIVE_RULE_MAP[normalized].get_info()
    for r in ROADMAP_RULES:
        if r.rule_id.upper() == normalized:
            return r
    return None
