"""Discover GitHub Actions workflow files without leaving the scan root."""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from gha_threatlens.constants import DEFAULT_MAX_WORKFLOW_BYTES, WORKFLOW_DIR, WORKFLOW_SUFFIXES
from gha_threatlens.errors import InvalidTargetError
from gha_threatlens.models import Diagnostic, DiagnosticKind


@dataclass(frozen=True)
class DiscoveredFile:
    path: Path
    relative_path: str
    size: int


@dataclass(frozen=True)
class DiscoveryResult:
    root: Path
    files: tuple[DiscoveredFile, ...]
    diagnostics: tuple[Diagnostic, ...]


def resolve_scan_root(target: str | Path) -> Path:
    path = Path(target)
    if not path.exists():
        raise InvalidTargetError(f"Scan target does not exist: {target}")
    if not path.is_dir():
        raise InvalidTargetError(f"Scan target is not a directory: {target}")
    return path.resolve()


def is_within_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def posix_relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def discover_workflows(
    target: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_WORKFLOW_BYTES,
) -> DiscoveryResult:
    root = resolve_scan_root(target)
    workflows = root / WORKFLOW_DIR
    files: list[DiscoveredFile] = []
    diagnostics: list[Diagnostic] = []

    if not workflows.exists():
        return DiscoveryResult(root=root, files=(), diagnostics=())
    if not workflows.is_dir():
        diagnostics.append(
            Diagnostic(
                kind=DiagnosticKind.UNSUPPORTED,
                path=posix_relative(workflows, root),
                message="Expected .github/workflows to be a directory.",
            )
        )
        return DiscoveryResult(root=root, files=(), diagnostics=tuple(diagnostics))

    if workflows.is_symlink() and not is_within_root(workflows, root):
        diagnostics.append(
            Diagnostic(
                kind=DiagnosticKind.SYMLINK_SKIPPED,
                path=WORKFLOW_DIR,
                message="Skipped .github/workflows because the directory symlink leaves the scan root.",
            )
        )
        return DiscoveryResult(root=root, files=(), diagnostics=tuple(diagnostics))

    for child in _iter_workflow_entries(workflows):
        relative = child.name
        display = f"{WORKFLOW_DIR}/{relative}"
        if child.is_symlink():
            resolved = child.resolve()
            if not is_within_root(resolved, root):
                diagnostics.append(
                    Diagnostic(
                        kind=DiagnosticKind.SYMLINK_SKIPPED,
                        path=display,
                        message="Skipped workflow symlink that resolves outside the scan root.",
                    )
                )
                continue
            if not resolved.is_file():
                diagnostics.append(
                    Diagnostic(
                        kind=DiagnosticKind.UNREADABLE,
                        path=display,
                        message="Workflow symlink does not resolve to a regular file.",
                    )
                )
                continue
            size = resolved.stat().st_size
            path = resolved
        elif child.is_file():
            size = child.stat().st_size
            path = child
        else:
            continue

        if size > max_bytes:
            diagnostics.append(
                Diagnostic(
                    kind=DiagnosticKind.SIZE_LIMIT,
                    path=display,
                    message=(
                        f"Skipped workflow larger than {max_bytes} bytes (file is {size} bytes)."
                    ),
                )
            )
            continue
        files.append(DiscoveredFile(path=path, relative_path=display, size=size))

    files.sort(key=lambda item: item.relative_path)
    return DiscoveryResult(root=root, files=tuple(files), diagnostics=tuple(diagnostics))


def _iter_workflow_entries(workflows: Path) -> Iterator[Path]:
    try:
        with os.scandir(workflows) as entries:
            children = sorted(entries, key=lambda entry: entry.name)
    except OSError:
        return
    for entry in children:
        name = entry.name
        if name.startswith("."):
            continue
        if not name.endswith(WORKFLOW_SUFFIXES):
            continue
        yield Path(entry.path)
