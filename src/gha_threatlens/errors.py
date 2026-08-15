"""CLI-mapped error hierarchy. Library code raises these; only the CLI exits."""

from __future__ import annotations


class ThreatLensError(Exception):
    """Base error for expected scanner failures."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class InvalidTargetError(ThreatLensError):
    """Scan path is missing, not a directory, or otherwise unusable."""


class DiscoveryError(ThreatLensError):
    """Workflow discovery failed before any file could be analysed."""


class FileSafetyError(ThreatLensError):
    """A file violated a documented safety bound (size, symlink, or type)."""


class YamlParseError(ThreatLensError):
    """A workflow file could not be parsed as YAML."""


class UnsupportedStructureError(ThreatLensError):
    """The document is YAML but not a usable GitHub Actions workflow mapping."""


class ReporterError(ThreatLensError):
    """A reporter could not serialise or write output."""


class InvariantError(ThreatLensError):
    """An internal consistency check failed."""
