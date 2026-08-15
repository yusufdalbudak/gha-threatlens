"""Canonical JSON report. Deterministic key order and relative paths only."""

from __future__ import annotations

import json

from gha_threatlens.models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=False, ensure_ascii=True) + "\n"
