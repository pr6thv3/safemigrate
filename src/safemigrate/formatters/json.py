"""Deterministic JSON v1.0 Formatter for SafeMigrate."""

import json
from safemigrate.models import ScanReport


def format_json(report: ScanReport, indent: int = 2) -> str:
    """Serializes a ScanReport to deterministic JSON v1.0 string."""
    data = report.model_dump(by_alias=True, mode="json")
    # Sort keys for deterministic output
    return json.dumps(data, indent=indent, sort_keys=True)
