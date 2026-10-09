"""Data models for SafeMigrate static migration analysis."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        ranks = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks[self]

    def breaches(self, threshold: "Severity") -> bool:
        return self.rank >= threshold.rank


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TransactionMode(str, Enum):
    WRAPPED = "wrapped"
    NOT_WRAPPED = "not_wrapped"
    UNKNOWN = "unknown"


class OutputFormat(str, Enum):
    HUMAN = "human"
    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"


class DiagnosticType(str, Enum):
    PARSE_ERROR = "parse_error"
    UNSUPPORTED_SYNTAX = "unsupported_syntax"
    INSUFFICIENT_CONTEXT = "insufficient_context"


class Diagnostic(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    type: DiagnosticType
    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    message: str


class AffectedObject(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_name: Optional[str] = Field(default=None, serialization_alias="schema")
    table: Optional[str] = None
    column: Optional[str] = None
    constraint: Optional[str] = None
    index: Optional[str] = None
    operation: str


class Finding(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    rule_id: str
    rule_title: str
    rule_version: str = "1.0.0"
    severity: Severity
    confidence: Confidence
    file: str
    line: int
    column: int
    statement: str
    affected_object: AffectedObject
    evidence: str
    explanation: str
    recommendation: str
    context_used: Dict[str, Any] = Field(default_factory=dict)
    context_not_known: List[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    total_files: int
    total_statements: int
    total_findings: int
    severities: Dict[str, int]
    parse_errors: int


class PolicyDecision(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    fail_on: Severity
    passed: bool
    exit_code: int


class ScanReport(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_version: str = "1.0"
    tool: Dict[str, str] = Field(default_factory=lambda: {"name": "safemigrate", "version": "0.1.0"})
    scan_timestamp: Optional[str] = None
    target_engine: str = "postgresql"
    pg_version: int = 18
    migration_transaction_mode: TransactionMode = TransactionMode.UNKNOWN
    scanned_files: List[str]
    diagnostics: List[Diagnostic] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    summary: ScanSummary
    policy: PolicyDecision


class RuleInfo(BaseModel):
    rule_id: str
    title: str
    version: str = "1.0.0"
    default_severity: Severity
    confidence: Confidence
    status: str
    description: str
    hazard_rationale: str
    positive_example: str
    negative_example: str
    remediation: str
