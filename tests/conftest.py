"""Pytest fixtures for SafeMigrate test suite."""

from pathlib import Path
import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def clean_fixtures_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "clean"


@pytest.fixture
def risky_fixtures_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "risky"


@pytest.fixture
def context_fixtures_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "context"


@pytest.fixture
def invalid_syntax_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "invalid_syntax"
