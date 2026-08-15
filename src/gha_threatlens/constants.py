"""Stable identifiers and documented operational limits."""

from __future__ import annotations

TOOL_NAME = "GHA-ThreatLens"
TOOL_ID = "gha-threatlens"
SCHEMA_VERSION = "1.0.0"
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

# Workflow YAML larger than this is skipped with a diagnostic rather than parsed.
DEFAULT_MAX_WORKFLOW_BYTES = 1_048_576

# Bound expression extraction so a hostile file cannot force unbounded scans.
MAX_EXPRESSION_LENGTH = 4_096

WORKFLOW_DIR = ".github/workflows"
WORKFLOW_SUFFIXES = (".yml", ".yaml")

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_USER = 2
EXIT_INTERNAL = 3
