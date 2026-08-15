from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gha_threatlens.engine import ScanOptions, scan
from gha_threatlens.models import ScanResult

FIXTURES = Path(__file__).parent / "fixtures"
FROZEN_TIME = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)


@pytest.fixture
def frozen_options() -> ScanOptions:
    return ScanOptions(clock=lambda: FROZEN_TIME)


def scan_workflow_text(tmp_path: Path, text: str, name: str = "workflow.yml") -> ScanResult:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(text, encoding="utf-8")
    return scan(tmp_path, ScanOptions(clock=lambda: FROZEN_TIME))


def fixture_text(*parts: str) -> str:
    return (FIXTURES.joinpath(*parts)).read_text(encoding="utf-8")
