"""Deterministic fingerprints for findings and attack paths."""

from __future__ import annotations

import hashlib


def fingerprint(*parts: str) -> str:
    payload = "|".join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
