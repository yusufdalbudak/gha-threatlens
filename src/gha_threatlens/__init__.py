"""Package version and public scan entry."""

from __future__ import annotations

from gha_threatlens.engine import scan, tool_version

__all__ = ["__version__", "scan"]
__version__ = tool_version()
