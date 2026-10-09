"""Base rule class and context for SafeMigrate static AST rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from safemigrate.models import (
    Confidence,
    Finding,
    RuleInfo,
    Severity,
    TransactionMode,
)
from safemigrate.parser import ParsedStatement


@dataclass
class ForeignKeyDefinition:
    constraint_name: str
    child_table: str
    referencing_columns: Tuple[str, ...]
    parent_table: str
    referenced_columns: Tuple[str, ...]
    file: str
    line: int
    column: int
    statement: str


@dataclass
class TableState:
    name: str
    schema_name: str = "public"
    columns: Set[str] = field(default_factory=set)
    indexes: List[Tuple[str, ...]] = field(default_factory=list)
    foreign_keys: List[ForeignKeyDefinition] = field(default_factory=list)
    staged_not_null_checks: Set[str] = field(default_factory=set)
    created_in_history: bool = False


@dataclass
class SchemaState:
    tables: Dict[str, TableState] = field(default_factory=dict)
    has_full_history: bool = True

    def get_or_create_table(self, table_name: str) -> TableState:
        normalized = table_name.lower().strip('"')
        if normalized not in self.tables:
            self.tables[normalized] = TableState(name=table_name)
        return self.tables[normalized]


@dataclass
class AnalysisContext:
    pg_version: int = 18
    migration_transaction_mode: TransactionMode = TransactionMode.UNKNOWN
    file_has_explicit_transaction: bool = False
    schema_state: SchemaState = field(default_factory=SchemaState)
    current_file_statements: List[ParsedStatement] = field(default_factory=list)


class Rule(ABC):
    """Abstract base class for all SafeMigrate AST-level analysis rules."""

    rule_id: str
    title: str
    version: str = "1.0.0"
    default_severity: Severity
    confidence: Confidence
    status: str = "First-Release (1.0)"
    description: str
    hazard_rationale: str
    positive_example: str
    negative_example: str
    remediation: str

    @abstractmethod
    def evaluate(
        self,
        statement: ParsedStatement,
        context: AnalysisContext,
    ) -> List[Finding]:
        """Evaluates an AST statement against this rule."""
        pass

    def get_info(self) -> RuleInfo:
        """Returns structured metadata for CLI rules catalog and documentation."""
        return RuleInfo(
            rule_id=self.rule_id,
            title=self.title,
            version=self.version,
            default_severity=self.default_severity,
            confidence=self.confidence,
            status=self.status,
            description=self.description,
            hazard_rationale=self.hazard_rationale,
            positive_example=self.positive_example,
            negative_example=self.negative_example,
            remediation=self.remediation,
        )
