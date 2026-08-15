"""Safe YAML loading that preserves locations and GitHub Actions `on` keys."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError

from gha_threatlens.errors import YamlParseError
from gha_threatlens.models import SourceLocation


@dataclass(frozen=True)
class ParsedDocument:
    data: Any
    text: str
    path: str


def load_yaml_document(path: Path, relative_path: str, text: str | None = None) -> ParsedDocument:
    """Load a workflow with YAML 1.2 round-trip construction.

    Round-trip mode preserves comments and line/column metadata. It does not
    instantiate arbitrary Python objects from YAML tags.
    """

    content = path.read_text(encoding="utf-8") if text is None else text
    yaml = _workflow_yaml()
    try:
        data = yaml.load(content)
    except YAMLError as exc:
        raise YamlParseError(f"YAML parse failed for {relative_path}: {exc}") from exc
    return ParsedDocument(data=data, text=content, path=relative_path)


def _workflow_yaml() -> YAML:
    yaml = YAML(typ="rt")
    yaml.version = (1, 2)
    yaml.preserve_quotes = True
    return yaml


def as_mapping(value: Any) -> CommentedMap | dict[Any, Any] | None:
    if isinstance(value, (CommentedMap, dict)):
        return value
    return None


def as_sequence(value: Any) -> CommentedSeq | list[Any] | None:
    if isinstance(value, (CommentedSeq, list, tuple)):
        return list(value) if not isinstance(value, CommentedSeq) else value
    return None


def scalar_text(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list, tuple, CommentedMap, CommentedSeq)):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def location_of_key(
    mapping: Any, key: Any, path: str, fallback: SourceLocation | None = None
) -> SourceLocation:
    line_col = _key_line_col(mapping, key)
    if line_col is None:
        return fallback or SourceLocation(path=path, start_line=1, start_column=1)
    line, column = line_col
    return SourceLocation(path=path, start_line=line, start_column=column)


def location_of_value(
    mapping: Any, key: Any, path: str, fallback: SourceLocation | None = None
) -> SourceLocation:
    line_col = _value_line_col(mapping, key)
    if line_col is None:
        return location_of_key(mapping, key, path, fallback)
    line, column = line_col
    return SourceLocation(path=path, start_line=line, start_column=column)


def location_of_node(
    node: Any, path: str, fallback: SourceLocation | None = None
) -> SourceLocation:
    lc = getattr(node, "lc", None)
    if lc is None:
        return fallback or SourceLocation(path=path, start_line=1, start_column=1)
    line = getattr(lc, "line", None)
    column = getattr(lc, "col", None)
    if line is None or column is None:
        return fallback or SourceLocation(path=path, start_line=1, start_column=1)
    return SourceLocation(path=path, start_line=int(line) + 1, start_column=int(column) + 1)


def excerpt_at(text: str, location: SourceLocation, max_chars: int = 160) -> str:
    lines = text.splitlines() or [""]
    index = max(location.start_line - 1, 0)
    if index >= len(lines):
        return ""
    line = lines[index].strip()
    if len(line) > max_chars:
        return f"{line[: max_chars - 1]}…"
    return line


def _key_line_col(mapping: Any, key: Any) -> tuple[int, int] | None:
    lc = getattr(mapping, "lc", None)
    if lc is None:
        return None
    try:
        line, column = lc.key(key)
    except (KeyError, TypeError, AttributeError, ValueError):
        return None
    if line is None or column is None:
        return None
    return int(line) + 1, int(column) + 1


def _value_line_col(mapping: Any, key: Any) -> tuple[int, int] | None:
    lc = getattr(mapping, "lc", None)
    if lc is None:
        return None
    try:
        line, column = lc.value(key)
    except (KeyError, TypeError, AttributeError, ValueError):
        return None
    if line is None or column is None:
        return None
    return int(line) + 1, int(column) + 1
