from __future__ import annotations

from pathlib import Path

import pytest

from gha_threatlens.constants import DEFAULT_MAX_WORKFLOW_BYTES
from gha_threatlens.discovery import discover_workflows
from gha_threatlens.errors import InvalidTargetError
from gha_threatlens.models import DiagnosticKind


def test_invalid_target(tmp_path: Path) -> None:
    with pytest.raises(InvalidTargetError):
        discover_workflows(tmp_path / "missing")
    file_target = tmp_path / "file.txt"
    file_target.write_text("x", encoding="utf-8")
    with pytest.raises(InvalidTargetError):
        discover_workflows(file_target)


def test_empty_repository_has_no_files(tmp_path: Path) -> None:
    result = discover_workflows(tmp_path)
    assert result.files == ()


def test_size_limit_skip(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    huge = workflows / "huge.yml"
    huge.write_text("x" * 50, encoding="utf-8")
    result = discover_workflows(tmp_path, max_bytes=10)
    assert result.files == ()
    assert result.diagnostics[0].kind is DiagnosticKind.SIZE_LIMIT


def test_symlink_outside_root_skipped(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yml"
    outside.write_text("name: x\n", encoding="utf-8")
    workflows = tmp_path / "scan" / ".github" / "workflows"
    workflows.mkdir(parents=True)
    link = workflows / "linked.yml"
    link.symlink_to(outside)
    result = discover_workflows(tmp_path / "scan")
    assert result.files == ()
    assert any(item.kind is DiagnosticKind.SYMLINK_SKIPPED for item in result.diagnostics)


def test_default_limit_constant() -> None:
    assert DEFAULT_MAX_WORKFLOW_BYTES == 1_048_576
